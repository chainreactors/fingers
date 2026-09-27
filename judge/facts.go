package judge

import (
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/chainreactors/fingers/common"
	"github.com/chainreactors/fingers/judge/internal/evidence"
)

// protocolFeatures are HTTP features some engines report as fingerprints
// (NormalizeName keys). The response head establishes them, or they are absent.
var protocolFeatures = map[string]bool{"hsts": true, "altsvc": true, "http3": true, "http2": true, "poweredby": true, "http基本认证": true}

const (
	maxClaims       = 40  // products judged per page; the rest stay unjudged (Judge == nil)
	maxEvidence     = 3   // excerpts per claim
	evidenceContext = 80  // bytes of response around a match
	maxExcerpt      = 240 // runes per excerpt
)

// groupProducts returns each product's spellings with the representative first.
// Names, evidence and rulings are derived from these original frameworks.
func groupProducts(frames common.Frameworks) [][]*common.Framework {
	byKey := map[string][]*common.Framework{}
	var keys []string
	for _, f := range frames {
		if f == nil {
			continue
		}
		key := NormalizeName(f.Name)
		if key == "" {
			continue
		}
		if len(byKey[key]) == 0 {
			keys = append(keys, key)
		}
		byKey[key] = append(byKey[key], f)
	}
	sort.Strings(keys)
	groups := make([][]*common.Framework, 0, len(keys))
	for _, key := range keys {
		group := byKey[key]
		sort.SliceStable(group, func(a, b int) bool {
			if qa, qb := frameworkQuality(group[a]), frameworkQuality(group[b]); qa != qb {
				return qa > qb
			}
			return group[a].Name < group[b].Name
		})
		groups = append(groups, group)
	}
	return groups
}

// declares accepts explicit software declarations, not incidental URL/cookie text.
func declares(p *evidence.Page, name string) bool {
	key := NormalizeName(name)
	if key == "" {
		return false
	}
	for header, values := range p.Header {
		h := strings.ToLower(header)
		if strings.HasPrefix(h, "x-") && NormalizeName(strings.TrimSuffix(strings.TrimPrefix(h, "x-"), "-version")) == key {
			return true
		}
		if h != "server" && h != "x-powered-by" && h != "product" {
			continue
		}
		for _, value := range values {
			for _, token := range strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ';' || r == '(' || r == ')' }) {
				token = strings.TrimSpace(token)
				if i := strings.IndexByte(token, '/'); i >= 0 {
					token = strings.TrimSpace(token[:i])
				}
				if NormalizeName(token) == key {
					return true
				}
				// A header can list several products separated by spaces.
				for _, part := range strings.Fields(value) {
					if !strings.Contains(part, "/") {
						continue
					}
					part = strings.SplitN(part, "/", 2)[0]
					if NormalizeName(part) == key {
						return true
					}
				}
			}
		}
	}
	return false
}

func protocolPresent(p *evidence.Page, key string) bool {
	switch key {
	case "hsts":
		return p.Header.Get("Strict-Transport-Security") != ""
	case "altsvc":
		return p.Header.Get("Alt-Svc") != ""
	case "poweredby":
		return p.Header.Get("X-Powered-By") != ""
	case "http2":
		return strings.HasPrefix(string(p.Raw), "HTTP/2") || strings.Contains(strings.ToLower(strings.Join(p.Header.Values("Alt-Svc"), ",")), "h2=")
	case "http3":
		return strings.HasPrefix(string(p.Raw), "HTTP/3") || strings.Contains(strings.ToLower(strings.Join(p.Header.Values("Alt-Svc"), ",")), "h3=")
	case "http基本认证":
		for _, value := range p.Header.Values("WWW-Authenticate") {
			// A comma inside a quoted realm does not start a new challenge.
			start, quoted, escaped := 0, false, false
			for i := 0; i <= len(value); i++ {
				if i == len(value) || (value[i] == ',' && !quoted) {
					words := strings.Fields(value[start:i])
					if len(words) > 0 && strings.EqualFold(words[0], "Basic") {
						return true
					}
					start = i + 1
				} else if escaped {
					escaped = false
				} else if value[i] == '\\' && quoted {
					escaped = true
				} else if value[i] == '"' {
					quoted = !quoted
				}
			}
		}
	}
	return false
}

// Prefer a representative that already carries a version and useful source
// metadata, since duplicate spellings are hidden from the accepted result.
func frameworkQuality(f *common.Framework) int {
	quality := len(f.Froms)
	if f.Attributes != nil {
		if f.Version != "" {
			quality += 100
		}
		if f.Vendor != "" {
			quality += 10
		}
	}
	if f.MatchDetail != nil {
		quality++
	}
	return quality
}

// evidenceFor quotes the response where the claim comes from: what each
// spelling's rule matched (MatchDetail, when the engine records it), then
// where the product's name occurs. A rule may rest on text deep in the
// page, which the compact page view does not carry.
func evidenceFor(raw []byte, frames []*common.Framework) []matchExcerpt {
	text := string(raw)
	lower := strings.ToLower(text)
	var out []matchExcerpt
	seen := map[int]bool{}
	add := func(start, end int, matched bool) {
		if start < 0 || len(out) >= maxEvidence {
			return
		}
		bucket := start / (2 * evidenceContext)
		if seen[bucket] {
			return
		}
		seen[bucket] = true
		e := excerpt(text, start, end)
		if matched {
			e.Matched = evidence.Truncate(evidence.Clean(strings.ToValidUTF8(text[start:end], "")), maxExcerpt)
		}
		out = append(out, e)
	}
	for _, f := range frames {
		d := f.MatchDetail
		if d == nil || d.MatcherValue == "" {
			continue
		}
		if strings.HasPrefix(d.MatcherType, "regexp") {
			if re, err := regexp.Compile("(?i)" + d.MatcherValue); err == nil {
				if loc := re.FindStringIndex(text); loc != nil {
					add(loc[0], loc[1], true)
				}
			}
			continue
		}
		v := strings.ToLower(d.MatcherValue)
		if i := strings.Index(lower, v); i >= 0 {
			add(i, i+len(v), true)
		}
	}
	for _, f := range frames {
		n := strings.ToLower(f.Name)
		if utf8.RuneCountInString(n) < 3 {
			continue
		}
		for from, found := 0, 0; found < 2; found++ {
			i := indexWord(lower[from:], n)
			if i < 0 {
				break
			}
			add(from+i, from+i+len(n), false)
			from += i + len(n)
		}
	}
	return out
}

func excerpt(text string, start, end int) matchExcerpt {
	where := "body"
	head := strings.Index(text, "\r\n\r\n")
	if head < 0 {
		head = strings.Index(text, "\n\n")
	}
	if head < 0 || start < head {
		where = "header"
	}
	lo, hi := start-evidenceContext, end+evidenceContext
	if lo < 0 {
		lo = 0
	}
	if hi > len(text) {
		hi = len(text)
	}
	return matchExcerpt{Where: where, Text: evidence.Truncate(evidence.Clean(strings.ToValidUTF8(text[lo:hi], "")), maxExcerpt)}
}

// containsWord matches ASCII keys on word boundaries ("acti" must not match
// "action"); CJK keys have no word boundaries and match as substrings.
func containsWord(haystack, key string) bool { return indexWord(haystack, key) >= 0 }

func indexWord(haystack, key string) int {
	if key == "" {
		return -1
	}
	if utf8.RuneCountInString(key) != len(key) {
		return strings.Index(haystack, key)
	}
	for from := 0; ; {
		i := strings.Index(haystack[from:], key)
		if i < 0 {
			return -1
		}
		start, end := from+i, from+i+len(key)
		if (start == 0 || !isWordByte(haystack[start-1])) && (end == len(haystack) || !isWordByte(haystack[end])) {
			return start
		}
		from = start + 1
	}
}

func isWordByte(b byte) bool {
	return b == '_' || b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}
