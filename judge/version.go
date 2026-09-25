package judge

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/chainreactors/fingers/common"
	"github.com/chainreactors/fingers/judge/internal/evidence"
)

const (
	notStated = "not_stated"

	maxVersions      = 40 // extracted from the raw response
	maxVersionsShown = 15 // options per product after ranking
	maxVersioned     = 8  // products versioned per page
)

// versionRound resolves the versions of frames that have none. Code decides
// first: a version the response binds to the product by name (a header such
// as "Server: nginx/1.24.0" or "X-Jenkins: 2.401.3", a generator meta such
// as "WordPress 7.0.3") is taken as is. For the rest the provider picks
// among extracted candidates, never generating a string: the candidates go
// into the state once, as a named list (Jev picked 100% right this way
// against 78% with them in the option descriptions), and each product's
// options are its own best-ranked ones. A version bound by name to another
// product is not offered, and one string is not given to two products.
func versionRound(r *round, frames ...*common.Framework) {
	var targets []*common.Framework
	for _, f := range frames {
		if f != nil && (f.Attributes == nil || f.Attributes.Version == "") && len(targets) < maxVersioned {
			targets = append(targets, f)
		}
	}
	if len(targets) == 0 {
		return
	}
	decls := declarations(r.page.raw)
	var asked []*common.Framework
	for _, f := range targets {
		if v := declaredVersion(decls, f.Name); v != "" {
			setVersion(f, v)
		} else {
			asked = append(asked, f)
		}
	}
	extracted := extractVersions(r.page.raw, maxVersions)
	if len(asked) == 0 || len(extracted) == 0 {
		return
	}
	type pick struct {
		f          *common.Framework
		value      string
		score      int
		confidence float64
	}
	picks := make([]pick, len(asked))
	var shown []versionString
	seen := map[string]bool{}
	for i, f := range asked {
		i, f := i, f
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
		scores := map[string]int{}
		opts := map[string]string{notStated: "The response does not show the version of " + f.Name}
		for _, c := range cands {
			opts[c.Value] = ""
			scores[c.Value] = versionScore(c, key)
			if !seen[c.Value] {
				seen[c.Value] = true
				shown = append(shown, c)
			}
		}
		r.add(fmt.Sprintf("version_%d", i), Choice(fmt.Sprintf("`version_strings` lists every version-like string found in the raw response, with the text around it. "+
			"Which one is the version of `%s`? A version in an asset URL parameter, a meta tag or embedded build info of %s counts. "+
			"Ignore versions of third-party libraries, other products mentioned in text, years, timestamps and build numbers.", f.Name, f.Name), opts),
			func(a Answer) {
				if a.Choice != "" && a.Choice != notStated && a.Confidence >= r.judge.VersionConfidence {
					picks[i] = pick{f: f, value: a.Choice, score: scores[a.Choice], confidence: a.Confidence}
				}
			})
	}
	if len(shown) == 0 {
		return
	}
	r.show("version_strings", shown)
	count := map[string]int{}
	for _, c := range extracted {
		count[c.Value] = c.count
	}
	r.then(func() {
		// A string that occurs once belongs to one product: the one whose
		// context names it best, then the more confident pick.
		best := map[string]int{}
		for i, p := range picks {
			if p.f == nil || count[p.value] > 1 {
				continue
			}
			if j, ok := best[p.value]; !ok || p.score > picks[j].score || p.score == picks[j].score && p.confidence > picks[j].confidence {
				best[p.value] = i
			}
		}
		for i, p := range picks {
			if p.f == nil {
				continue
			}
			if j, ok := best[p.value]; ok && j != i {
				continue
			}
			setVersion(p.f, p.value)
		}
	})
}

// setVersion copies on write: Attributes may be shared with other frameworks.
func setVersion(f *common.Framework, version string) {
	attrs := common.NewAttributesWithAny()
	if f.Attributes != nil {
		copied := *f.Attributes
		attrs = &copied
	}
	attrs.Version = version
	f.Attributes = attrs
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
		if m := reLeadingVersion.FindStringSubmatch(value); m != nil {
			name := strings.TrimSuffix(strings.TrimPrefix(strings.ToLower(key), "x-"), "-version")
			out = append(out, declaration{name, m[1]})
		}
		pairs(value)
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
		if looksLikeIPv4(v) {
			continue
		}
		start, end := loc[0]-60, loc[1]+30
		if start < 0 {
			start = 0
		}
		if end > len(text) {
			end = len(text)
		}
		ctx := clean(strings.ToValidUTF8(text[start:end], ""))
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
			out = append(out, versionString{Value: v, Context: clean(strings.ToValidUTF8(text[m[0]:m[1]], "")), count: 1})
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
