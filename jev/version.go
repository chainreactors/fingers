package jev

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/chainreactors/fingers/common"
)

// VersionConfidence is the confidence at or above which a version is written.
// Tuned for DefaultModel: 42 of 46 such answers were right on real pages.
var VersionConfidence = 0.9

const (
	NotStated = "not_stated"

	maxVersions      = 40 // extracted from the raw response
	maxVersionsShown = 15 // shown to Jev after ranking
)

// Version adds to r the question which extracted version string is the
// version of f, and writes it to f when Jev is confident. It does nothing when
// f is nil, already has a version, or the page shows no version-like string.
// Jev cannot generate strings: code extracts, Jev only picks.
func Version(r *Round, f *common.Framework) {
	if f == nil || (f.Attributes != nil && f.Attributes.Version != "") {
		return
	}
	cands := rankVersions(extractVersions(r.page.raw, maxVersions), f.Name, maxVersionsShown)
	if len(cands) == 0 {
		return
	}
	// The candidates go into the state as a named list: Jev reads literally,
	// and picked 100% right this way against 78% with them in the options.
	opts := map[string]interface{}{NotStated: "The response does not show the version of " + f.Name}
	for _, c := range cands {
		opts[c.Value] = nil
	}
	r.Evidence("version_strings", cands)
	r.Add("version", Choice(fmt.Sprintf("`version_strings` lists every version-like string found in the raw response, with the text around it. "+
		"Which one is the version of `%s`? A version in an asset URL parameter, a meta tag or embedded build info of %s counts. "+
		"Ignore versions of third-party libraries, other products mentioned in text, years, timestamps and build numbers.", f.Name, f.Name), opts),
		func(a Answer) {
			if a.Choice == "" || a.Choice == NotStated || a.Confidence < VersionConfidence {
				return
			}
			// copy on write: Attributes may be shared with other frameworks
			attrs := common.NewAttributesWithAny()
			if f.Attributes != nil {
				copied := *f.Attributes
				attrs = &copied
			}
			attrs.Version = a.Choice
			f.Attributes = attrs
		})
}

// versionString is a version-like string with the raw text around its first
// occurrence, so Jev can tell a product version from a library version. The
// JSON names are what Jev reads.
type versionString struct {
	Value   string `json:"value"`
	Context string `json:"found_in"`
}

// extractVersions scans the raw response (headers and body, including
// inline scripts and meta tags that Page drops). Jev cannot generate
// strings, so versions are extracted by regex and Jev only picks one.
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
			if contextWeight(ctx) > contextWeight(out[i].Context) {
				out[i].Context = ctx
			}
			continue
		}
		if len(out) >= max {
			continue
		}
		seen[v] = len(out)
		out = append(out, versionString{Value: v, Context: ctx})
	}
	// "Drupal 10": a generator meta that states only a major version.
	for _, m := range reGenMajor.FindAllStringSubmatchIndex(text, -1) {
		lo, hi := m[2], m[3]
		if lo < 0 {
			lo, hi = m[4], m[5]
		}
		if v := text[lo:hi]; len(out) < max {
			if _, ok := seen[v]; ok {
				continue
			}
			seen[v] = len(out)
			out = append(out, versionString{Value: v, Context: clean(strings.ToValidUTF8(text[m[0]:m[1]], ""))})
		}
	}
	return out
}

// contextWeight prefers contexts that declare a version (generator meta,
// product headers) over asset URLs that merely carry one.
func contextWeight(ctx string) int {
	c := strings.ToLower(ctx)
	switch {
	case strings.Contains(c, "generator"):
		return 3
	case strings.Contains(c, "server:") || strings.Contains(c, "x-powered-by:") || strings.Contains(c, "product:"):
		return 2
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

// rankVersions orders candidates by how likely their context names
// the version of product, and keeps the first max. Pages often carry dozens
// of "?ver=" strings, so without ranking the one real version (a generator
// meta or a header) can fall outside the list Jev sees.
func rankVersions(cands []versionString, product string, max int) []versionString {
	key := NormalizeName(product)
	score := func(c versionString) int {
		ctx := strings.ToLower(c.Context)
		s := 0
		if strings.Contains(ctx, "generator") {
			s += 4
		}
		for _, h := range []string{"server:", "x-powered-by:", "product:", "x-generator:", "version:"} {
			if strings.Contains(ctx, h) {
				s += 3
				break
			}
		}
		if key != "" && strings.Contains(NormalizeName(ctx), key) {
			s += 2
		}
		for _, noisy := range []string{"/plugins/", "/themes/", "/vendor/", "jquery", "bootstrap", "schema_version"} {
			if strings.Contains(ctx, noisy) {
				s -= 2
				break
			}
		}
		return s
	}
	out := append([]versionString(nil), cands...)
	sort.SliceStable(out, func(a, b int) bool { return score(out[a]) > score(out[b]) })
	if len(out) > max {
		out = out[:max]
	}
	return out
}
