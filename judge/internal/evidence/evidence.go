// Package evidence holds the text primitives shared by the judge and the
// fingerprint generator: product name folding, name candidates found in a
// response, and the patterns for titles, generator metas and versions.
package evidence

import (
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// VersionToken matches a version, keeping release suffixes and calendar
// versions (e.g. 1.0.2q, 1.0.0-rc.35, 2026.9.23+3cd69d30e).
const VersionToken = `[0-9]{1,4}(?:\.[0-9]{1,4}){1,3}(?:[A-Za-z]+[0-9]*|[-+][0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?`

var (
	Title     = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	Generator = regexp.MustCompile(`(?is)<meta[^>]+name=["']generator["'][^>]*content=["']([^"']+)|<meta[^>]+content=["']([^"']+)["'][^>]*name=["']generator["']`)
	// NameVersion is a trailing version after a product name ("nginx/1.24", "Jenkins v2").
	NameVersion = regexp.MustCompile(`(?i)[/\s]+[vV]?(?:` + VersionToken + `|[0-9]+)\s*$`)

	space     = regexp.MustCompile(`\s+`)
	nameWords = regexp.MustCompile(`[A-Z][A-Za-z0-9!+._]{2,}(?:[ -][A-Z][A-Za-z0-9!+._]{2,}){0,2}|[\p{Han}]{2,20}`)
)

// Clean decodes common entities and collapses whitespace.
func Clean(s string) string {
	s = strings.NewReplacer("&nbsp;", " ", "&amp;", "&", "&lt;", "<", "&gt;", ">", "&quot;", `"`).Replace(s)
	return strings.TrimSpace(space.ReplaceAllString(s, " "))
}

var genericSuffixes = []string{"companyproducts", "公司产品", "product", "products", "产品", "operatingsystem", "操作系统", "system"}

// genericWords are trailing words engines add to a product name ("Apache
// HTTP Server", "apache-web-server", "Discuz! X"). They are dropped only as
// whole words, so "lighttpd" keeps its "httpd".
var genericWords = map[string]bool{"http": true, "httpd": true, "server": true, "web": true, "webserver": true, "x": true, "cms": true, "oa": true}

// NormalizeName folds the spellings different engines use for one product
// ("Apache-Tomcat", "apache tomcat", "Apache HTTP Server", "apache") into one
// key. It never merges names whose remaining letters differ.
func NormalizeName(name string) string {
	words := strings.FieldsFunc(strings.ToLower(name), func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) })
	for len(words) > 1 && genericWords[words[len(words)-1]] {
		words = words[:len(words)-1]
	}
	key := strings.Join(words, "")
	for _, s := range genericSuffixes {
		if len(key) > len(s)+2 && strings.HasSuffix(key, s) {
			key = strings.TrimSuffix(key, s)
		}
	}
	return key
}

// UsableKey drops keys too short to be meaningful evidence ("oa", "cms").
func UsableKey(k string) bool {
	n := utf8.RuneCountInString(k)
	if n == len(k) { // ascii
		return n >= 4
	}
	return n >= 2
}

// GenericName reports whether a normalized name is a generic interface word
// ("login", "控制台") rather than a product.
func GenericName(key string) bool {
	switch key {
	case "login", "signin", "welcome", "dashboard", "admin", "console", "home", "index", "server", "error", "notfound", "password", "username", "management", "system", "登录", "首页", "管理", "用户", "密码", "控制台":
		return true
	}
	return false
}

// Names returns up to 20 product name candidates found in a response, most
// telling source first: generator meta, product headers, title parts, asset
// path words, then capitalized words and CJK runs of the visible text.
func Names(generator, title, text string, headers map[string]string, assets []string) []string {
	type candidate struct {
		name   string
		weight int
	}
	byKey := map[string]candidate{}
	add := func(text string, weight int) {
		text = strings.Trim(strings.TrimSpace(NameVersion.ReplaceAllString(Clean(text), "")), "-:|/ ")
		if text == "" || utf8.RuneCountInString(text) > 40 || !UsableKey(strings.ToLower(text)) {
			return
		}
		key := NormalizeName(text)
		if key == "" || GenericName(key) {
			return
		}
		if prev, ok := byKey[key]; !ok || weight > prev.weight {
			byKey[key] = candidate{text, weight}
		}
	}
	add(generator, 5)
	for k, v := range headers {
		if strings.HasPrefix(k, "X-") || k == "Server" || k == "Product" {
			add(strings.Split(v, "/")[0], 4)
		}
	}
	for _, part := range strings.FieldsFunc(title, func(r rune) bool { return r == '|' || r == '-' || r == ':' || r == '–' }) {
		add(part, 4)
	}
	for _, asset := range assets {
		for _, word := range strings.FieldsFunc(asset, func(r rune) bool { return r == '/' || r == '_' }) {
			add(word, 2)
		}
	}
	for _, segment := range strings.FieldsFunc(text, func(r rune) bool { return r == '.' || r == ':' || r == '。' || r == '：' || r == '|' || r == '，' }) {
		for _, match := range nameWords.FindAllString(segment, 20) {
			add(match, 1)
		}
	}
	list := make([]candidate, 0, len(byKey))
	for _, c := range byKey {
		list = append(list, c)
	}
	sort.Slice(list, func(a, b int) bool {
		if list[a].weight != list[b].weight {
			return list[a].weight > list[b].weight
		}
		return list[a].name < list[b].name
	})
	if len(list) > 20 {
		list = list[:20]
	}
	out := make([]string, len(list))
	for i, c := range list {
		out[i] = c.name
	}
	return out
}
