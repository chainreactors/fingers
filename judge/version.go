package judge

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/chainreactors/fingers/common"
	"github.com/chainreactors/fingers/judge/internal/evidence"
	"github.com/chainreactors/utils/jev"
)

var (
	// Allows a v/V/x/X prefix ("X3.4", "V8.1SP2") and a letter suffix; rejects
	// digits glued to other digits or dots so IPs and long builds stay out.
	reGenMajor = regexp.MustCompile(`(?i)generator["'][^>]*content=["'][A-Za-z][^"']*?\s[vV]?(\d{1,3})(?:[\s"'(]|$)|content=["'][A-Za-z][^"']*?\s[vV]?(\d{1,3})(?:[\s(][^"']*)?["'][^>]*name=["']generator`)
	reVersion  = regexp.MustCompile(`(?:^|[^0-9A-Za-z.])[vVxX]?(` + evidence.VersionToken + `)(?:[^0-9A-Za-z.]|\.[A-Za-z]|$)`)
	// What precedes numbers reVersion catches that are never versions: the
	// viewport's "initial-scale=1.0".
	reNotVersion = regexp.MustCompile(`(?i)(?:initial|minimum|maximum)-scale\s*=\s*$`)
)

const (
	notStated = "not_stated"

	maxVersions      = 40 // extracted from the raw response
	maxVersionsShown = 15 // options per product after ranking
	maxVersioned     = 8  // products versioned per page
)

// versions uses one finite-option claim per product, including local declarations.
func (j *Judge) versions(ctx context.Context, p *evidence.Page, frames ...*common.Framework) error {
	decls := declarations(p.Raw)
	extracted := extractVersions(p.Raw, maxVersions)
	claims := map[string]jev.Claim{}
	targets := map[string]*common.Framework{}
	var shown []versionString
	seen := map[string]bool{}
	count := 0
	for _, f := range frames {
		if f == nil || protocolFeatures[NormalizeName(f.Name)] || (f.Attributes != nil && f.Version != "") {
			continue
		}
		if count >= maxVersioned {
			break
		}
		count++
		claim := jev.Claim{Statement: fmt.Sprintf("`version_strings` lists version-like strings with their context. Which is the version of `%s`? A product's asset URL parameter, generator meta or embedded build info counts. Ignore third-party libraries, other products, protocols, years, timestamps and build numbers.", f.Name), Options: map[string]jev.Option{
			notStated:              {Description: "The response does not state the version of " + f.Name, Outcome: jev.Refuted},
			jev.OptionInsufficient: {Description: insufficientDescription, Outcome: jev.Insufficient},
		}}
		if v := declaredVersion(decls, f.Name); v != "" {
			claim.Options[v] = jev.Option{Description: "The response explicitly binds this version to " + f.Name, Outcome: jev.Holds}
			if err := j.applyVersion(f, claim, jev.Ruling{Option: v, Confidence: 1}); err != nil {
				return err
			}
			continue
		}
		key := NormalizeName(f.Name)
		var own []versionString
		for _, c := range extracted {
			if c.count == 1 && claimedByOther(decls, c.Value, key) {
				continue
			}
			own = append(own, c)
		}
		cands := rankVersions(own, f.Name, maxVersionsShown)
		if len(cands) == 0 {
			continue
		}
		for _, c := range cands {
			claim.Options[c.Value] = jev.Option{Outcome: jev.Holds}
			if !seen[c.Value] {
				seen[c.Value] = true
				shown = append(shown, c)
			}
		}
		id := "version_" + key
		claims[id], targets[id] = claim, f
	}
	rulings, err := j.judge(ctx, map[string]interface{}{"response": p, "version_strings": shown}, claims)
	if err != nil {
		return err
	}
	for id, ruling := range rulings {
		if err := j.applyVersion(targets[id], claims[id], ruling); err != nil {
			return err
		}
	}
	return nil
}

func (j *Judge) applyVersion(f *common.Framework, claim jev.Claim, ruling jev.Ruling) error {
	if err := validRuling(claim, ruling); err != nil {
		return err
	}
	if claim.Resolve(ruling, j.MinConfidence) == jev.Holds {
		if f.Attributes == nil {
			f.Attributes = common.NewAttributesWithAny()
		}
		f.Version = ruling.Option
	}
	return nil
}

// declaration is a version the response binds to a product name.
type declaration struct{ name, version string }

var (
	reDeclared       = regexp.MustCompile(`([A-Za-z][A-Za-z0-9._-]*(?: [A-Za-z][A-Za-z0-9._-]*){0,2})(?:/| +[vV]?)(` + evidence.VersionToken + `)(?:[^0-9A-Za-z.+-]|$)`)
	reLeadingVersion = regexp.MustCompile(`^[vV]?(` + evidence.VersionToken + `)(?:[\s;,(]|$)`)
)

// declarations finds "name/version" and "name version" pairs in response
// headers and generator metas, and headers whose name is the product
// ("X-Jenkins: 2.401.3", "X-AspNet-Version: 4.0.30319").
func declarations(raw []byte) []declaration {
	text := string(raw)
	head, body := text, ""
	if i := strings.Index(text, "\r\n\r\n"); i >= 0 {
		head, body = text[:i], text[i+4:]
	} else if i := strings.Index(text, "\n\n"); i >= 0 {
		head, body = text[:i], text[i+2:]
	}
	var out []declaration
	pairs := func(value string) {
		for _, m := range reDeclared.FindAllStringSubmatch(value, -1) {
			out = append(out, declaration{m[1], m[2]})
		}
	}
	lines := strings.Split(head, "\n")
	for _, line := range lines[1:] { // skip the status line
		line = strings.TrimSpace(line)
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		key, value := line[:colon], strings.TrimSpace(line[colon+1:])
		if m := reLeadingVersion.FindStringSubmatch(value); m != nil && strings.HasPrefix(strings.ToLower(key), "x-") {
			name := strings.TrimSuffix(strings.TrimPrefix(strings.ToLower(key), "x-"), "-version")
			out = append(out, declaration{name, m[1]})
		}
		if strings.EqualFold(key, "Server") || strings.EqualFold(key, "X-Powered-By") || strings.EqualFold(key, "Product") {
			pairs(value)
		}
		if strings.HasPrefix(strings.ToLower(key), "x-") {
			product := NormalizeName(strings.TrimSuffix(strings.TrimPrefix(strings.ToLower(key), "x-"), "-version"))
			for _, m := range reDeclared.FindAllStringSubmatch(value, -1) {
				d := declaration{m[1], m[2]}
				if d.names(product) {
					out = append(out, d)
				}
			}
		}
	}
	for _, m := range evidence.Generator.FindAllStringSubmatch(body, 4) {
		pairs(m[1] + m[2])
	}
	return out
}

// names reports whether a declared name is the product with key: the whole
// name or its trailing words, so "Apache Tomcat/9.0" names tomcat, not apache.
func (d declaration) names(key string) bool {
	if key == "" {
		return false
	}
	words := strings.Fields(d.name)
	for i := range words {
		if NormalizeName(strings.Join(words[i:], " ")) == key {
			return true
		}
	}
	return false
}

// declaredVersion is the version the response binds to product, if exactly one.
func declaredVersion(decls []declaration, product string) string {
	key := NormalizeName(product)
	found := ""
	for _, d := range decls {
		if d.names(key) {
			if found != "" && found != d.version {
				return ""
			}
			found = d.version
		}
	}
	return found
}

// claimedByOther reports whether value is bound by name to a product other than key.
func claimedByOther(decls []declaration, value, key string) bool {
	for _, d := range decls {
		if d.version == value && !d.names(key) {
			return true
		}
	}
	return false
}

// versionString is a version-like string with the raw text around its first
// occurrence, so the provider can tell a product version from a library version. The
// JSON names are what the provider reads.
type versionString struct {
	Value   string `json:"value"`
	Context string `json:"found_in"`
	count   int    // occurrences in the response
}

// extractVersions scans the raw response (headers and body, including
// inline scripts and meta tags that Page drops). Providers do not
// generate strings: versions are extracted by regex and one is picked.
func extractVersions(raw []byte, max int) []versionString {
	text := string(raw)
	if i := strings.IndexByte(text, '\n'); i >= 0 { // skip the "HTTP/1.1 200" status line
		text = text[i+1:]
	}
	seen := map[string]int{} // value -> index in out
	var out []versionString
	for _, loc := range reVersion.FindAllStringSubmatchIndex(text, -1) {
		v := text[loc[2]:loc[3]]
		before := loc[2] - 20
		if before < 0 {
			before = 0
		}
		if looksLikeIPv4(v) || strings.Trim(v, "0.") == "" || reNotVersion.MatchString(text[before:loc[2]]) {
			continue
		}
		start, end := loc[0]-60, loc[1]+30
		if start < 0 {
			start = 0
		}
		if end > len(text) {
			end = len(text)
		}
		ctx := evidence.Clean(strings.ToValidUTF8(text[start:end], ""))
		// A value repeats across a page ("?ver=7.1" on every asset, then
		// the generator meta); keep the context that best states a version.
		if i, ok := seen[v]; ok {
			out[i].count++
			if contextWeight(ctx) > contextWeight(out[i].Context) {
				out[i].Context = ctx
			}
			continue
		}
		seen[v] = len(out)
		out = append(out, versionString{Value: v, Context: ctx, count: 1})
	}
	// "Drupal 10": a generator meta that states only a major version.
	for _, m := range reGenMajor.FindAllStringSubmatchIndex(text, -1) {
		lo, hi := m[2], m[3]
		if lo < 0 {
			lo, hi = m[4], m[5]
		}
		if v := text[lo:hi]; v != "" {
			if _, ok := seen[v]; ok {
				continue
			}
			seen[v] = len(out)
			out = append(out, versionString{Value: v, Context: evidence.Clean(strings.ToValidUTF8(text[m[0]:m[1]], "")), count: 1})
		}
	}
	// Select evidence after scanning: SVG numbers or early library assets must
	// not crowd later generator/header/script versions out of the shortlist.
	if len(out) > max {
		sort.SliceStable(out, func(i, j int) bool { return contextWeight(out[i].Context) > contextWeight(out[j].Context) })
		out = out[:max]
	}
	return out
}

// contextWeight prefers contexts that declare a version (generator meta,
// product headers) over asset URLs that merely carry one.
func contextWeight(ctx string) int {
	c := strings.ToLower(ctx)
	switch {
	case strings.Contains(c, "generator"):
		return 5
	case strings.Contains(c, "server:") || strings.Contains(c, "x-powered-by:") || strings.Contains(c, "product:"):
		return 4
	case strings.Contains(c, "<script") || strings.Contains(c, "<link") || strings.Contains(c, ".js") || strings.Contains(c, ".css"):
		return 3
	case strings.Contains(c, "/plugins/") || strings.Contains(c, "/themes/"):
		return 0
	}
	return 1
}

// looksLikeIPv4 filters "10.0.0.5"; real four-part versions rarely start at 10+
// with every part <= 255.
func looksLikeIPv4(v string) bool {
	parts := strings.Split(v, ".")
	if len(parts) != 4 {
		return false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n > 255 || (i == 0 && n < 10) {
			return false
		}
	}
	return true
}

// rankVersions orders candidates by how likely their context states the
// version of product, and keeps the first max. Pages often carry dozens of
// "?ver=" strings, so without ranking the one real version can fall outside
// the list the provider sees.
func rankVersions(cands []versionString, product string, max int) []versionString {
	key := NormalizeName(product)
	out := append([]versionString(nil), cands...)
	sort.SliceStable(out, func(a, b int) bool { return versionScore(out[a], key) > versionScore(out[b], key) })
	if len(out) > max {
		out = out[:max]
	}
	return out
}

// versionScore rates how well c's context ties it to the product with key.
// Naming the product counts most, the more so right before the value; words
// that declare some version (generator, Server:) count less, since they do
// not say whose; library and plugin paths count against.
func versionScore(c versionString, key string) int {
	ctx := strings.ToLower(c.Context)
	s := 0
	if key != "" {
		if strings.Contains(NormalizeName(ctx), key) {
			s += 3
		}
		before := ctx
		if i := strings.Index(ctx, strings.ToLower(c.Value)); i >= 0 {
			before = ctx[:i]
		}
		if len(before) > 24 {
			before = before[len(before)-24:]
		}
		if strings.Contains(NormalizeName(before), key) {
			s += 3
		}
	}
	for _, h := range []string{"generator", "server:", "x-powered-by:", "product:", "version"} {
		if strings.Contains(ctx, h) {
			s += 2
			break
		}
	}
	for _, noisy := range []string{"/plugins/", "/themes/", "/vendor/", "jquery", "bootstrap", "schema_version"} {
		if strings.Contains(ctx, noisy) && !strings.Contains(key, NormalizeName(noisy)) {
			s -= 2
			break
		}
	}
	return s
}
