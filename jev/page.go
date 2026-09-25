package jev

import (
	"bufio"
	"bytes"
	"hash/fnv"
	"io"
	"net/http"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Page is the entry point of the judgement layer: the compact, named view of
// one HTTP response that Jev judges (serialized as the request state), plus
// the page-level conclusions written back by Classify. Jev only judges the
// evidence it is given and loses accuracy on large states full of irrelevant
// detail, so the fields below are the ones that carry fingerprint signal.
type Page struct {
	Status      string            `json:"status"`
	Headers     map[string]string `json:"headers,omitempty"`
	Cookies     []string          `json:"cookie_names,omitempty"`
	Title       string            `json:"title,omitempty"`
	Generator   string            `json:"meta_generator,omitempty"`
	Scripts     []string          `json:"script_src,omitempty"`
	Styles      []string          `json:"stylesheet_href,omitempty"`
	InlineHints []string          `json:"inline_script_starts,omitempty"` // first chars of inline scripts, e.g. "(function(w,d,s,l,i){ ... GTM"
	Comments    []string          `json:"html_comments,omitempty"`
	Forms       []string          `json:"form_inputs,omitempty"`
	Text        string            `json:"visible_text,omitempty"`

	Kind    string `json:"-"` // one of PageKinds, set by Classify
	Generic bool   `json:"-"` // stock page of a packaged product, set by Classify

	raw []byte
}

var (
	// Headers that carry no fingerprint signal, or only noise; every other
	// header is kept, since products announce themselves in custom headers
	// ("product: Z-BlogPHP 1.7.4", "X-Jenkins", "kbn-name").
	skipHeaders = map[string]bool{"Date": true, "Content-Length": true, "Content-Type": true, "Expires": true, "Cache-Control": true,
		"Pragma": true, "Etag": true, "Last-Modified": true, "Age": true, "Connection": true, "Keep-Alive": true, "Accept-Ranges": true,
		"Vary": true, "Set-Cookie": true, "Content-Security-Policy": true, "Content-Security-Policy-Report-Only": true, "Report-To": true,
		"Nel": true, "Permissions-Policy": true,
		// per-request values: no signal, and they would defeat the cache
		"X-Request-Id": true, "X-Amzn-Trace-Id": true, "Cf-Ray": true, "X-Runtime": true, "Server-Timing": true}

	reTitle     = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	reGenerator = regexp.MustCompile(`(?is)<meta[^>]+name=["']generator["'][^>]*content=["']([^"']+)|<meta[^>]+content=["']([^"']+)["'][^>]*name=["']generator["']`)
	reScript    = regexp.MustCompile(`(?is)<script[^>]+src=["']([^"']+)`)
	reStyle     = regexp.MustCompile(`(?is)<link[^>]+rel=["']?stylesheet[^>]*href=["']([^"']+)|<link[^>]+href=["']([^"']+)["'][^>]*rel=["']?stylesheet`)
	reInline    = regexp.MustCompile(`(?is)<script(?:\s[^>]*)?>(.*?)</script>`)
	reComment   = regexp.MustCompile(`(?s)<!--(.*?)-->`)
	reInput     = regexp.MustCompile(`(?is)<input[^>]*>`)
	reAttrName  = regexp.MustCompile(`(?is)\b(?:name|id)=["']([^"']+)`)
	reAttrType  = regexp.MustCompile(`(?is)\btype=["']([^"']+)`)
	reDropBlock = regexp.MustCompile(`(?is)<(script|style|noscript)[^>]*>.*?</(script|style|noscript)>`)
	reTag       = regexp.MustCompile(`(?s)<[^>]+>`)
	reSpace     = regexp.MustCompile(`\s+`)
	// Allows a v/V/x/X prefix ("X3.4", "V8.1SP2") and a letter suffix; rejects
	// digits glued to other digits or dots so IPs and long builds stay out.
	reGenMajor = regexp.MustCompile(`(?i)generator["'][^>]*content=["'][A-Za-z][^"']*?\s[vV]?(\d{1,3})(?:[\s"'(]|$)|content=["'][A-Za-z][^"']*?\s[vV]?(\d{1,3})(?:[\s(][^"']*)?["'][^>]*name=["']generator`)
	reVersion  = regexp.MustCompile(`(?:^|[^0-9A-Za-z.])[vVxX]?(\d{1,3}\.\d{1,3}(?:\.\d{1,4}){0,2})(?:[^0-9.]|$)`)
)

const (
	maxHeaderValue = 160
	maxText        = 1500 // visible text runes
)

// NewPage parses a raw HTTP response (head and body, as rule engines take it).
func NewPage(raw []byte) (*Page, error) {
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(raw)), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	s := &Page{Status: resp.Status, Headers: map[string]string{}, raw: raw}
	for k, vs := range resp.Header {
		if skipHeaders[k] || strings.HasPrefix(k, "X-Crawler-") || len(vs) == 0 {
			continue
		}
		s.Headers[k] = truncate(strings.Join(vs, ", "), maxHeaderValue)
	}
	for _, c := range resp.Cookies() {
		s.Cookies = append(s.Cookies, c.Name)
	}
	html := string(body)
	if m := reTitle.FindStringSubmatch(html); m != nil {
		s.Title = clean(m[1])
	}
	if m := reGenerator.FindStringSubmatch(html); m != nil {
		s.Generator = m[1] + m[2]
	}
	for _, m := range reScript.FindAllStringSubmatch(html, 8) {
		s.Scripts = append(s.Scripts, m[1])
	}
	for _, m := range reStyle.FindAllStringSubmatch(html, 8) {
		s.Styles = append(s.Styles, m[1]+m[2])
	}
	for _, m := range reInline.FindAllStringSubmatch(html, -1) {
		if code := clean(m[1]); len(code) > 20 && len(s.InlineHints) < 5 {
			s.InlineHints = append(s.InlineHints, truncate(code, 100))
		}
	}
	for _, m := range reComment.FindAllStringSubmatch(html, -1) {
		if c := clean(m[1]); len(c) > 3 && len(s.Comments) < 5 && !strings.HasPrefix(c, "[if") {
			s.Comments = append(s.Comments, truncate(c, 80))
		}
	}
	for _, in := range reInput.FindAllString(html, 12) {
		name, typ := "", "text"
		if m := reAttrName.FindStringSubmatch(in); m != nil {
			name = m[1]
		}
		if m := reAttrType.FindStringSubmatch(in); m != nil {
			typ = m[1]
		}
		if name != "" {
			s.Forms = append(s.Forms, name+":"+typ)
		}
	}
	text := clean(reTag.ReplaceAllString(reDropBlock.ReplaceAllString(html, " "), " "))
	s.Text = truncate(text, maxText)
	return s, nil
}

// Haystack is the lowercase text that candidate names are searched in.
func (s *Page) Haystack() string {
	var b strings.Builder
	for k, v := range s.Headers {
		b.WriteString(k + ": " + v + "\n")
	}
	b.WriteString(strings.Join(s.Cookies, " ") + "\n")
	b.WriteString(s.Title + "\n" + s.Generator + "\n")
	b.WriteString(strings.Join(s.Scripts, " ") + "\n")
	b.WriteString(strings.Join(s.Styles, " ") + "\n")
	b.WriteString(strings.Join(s.InlineHints, " ") + "\n")
	b.WriteString(strings.Join(s.Comments, " ") + "\n")
	b.WriteString(s.Text)
	return strings.ToLower(b.String())
}

func clean(s string) string {
	s = strings.NewReplacer("&nbsp;", " ", "&amp;", "&", "&lt;", "<", "&gt;", ">", "&quot;", `"`).Replace(s)
	return strings.TrimSpace(reSpace.ReplaceAllString(s, " "))
}

func truncate(s string, max int) string {
	if utf8.RuneCountInString(s) <= max {
		return s
	}
	return string([]rune(s)[:max]) + "…"
}

// Evidence reports where a candidate name literally occurs in the page. It is
// a cheap code-only baseline for false positive detection: a name found only
// in visible text is a likely false positive.
func (s *Page) Evidence(name string) []string {
	n := strings.ToLower(name)
	if len(n) < 3 {
		return nil
	}
	var where []string
	check := func(label, text string) {
		if strings.Contains(strings.ToLower(text), n) {
			where = append(where, label)
		}
	}
	var headers strings.Builder
	for k, v := range s.Headers {
		headers.WriteString(k + ":" + v + " ")
	}
	check("header", headers.String())
	check("cookie", strings.Join(s.Cookies, " "))
	check("title", s.Title)
	check("meta", s.Generator)
	check("script", strings.Join(s.Scripts, " ")+" "+strings.Join(s.InlineHints, " "))
	check("style", strings.Join(s.Styles, " "))
	check("comment", strings.Join(s.Comments, " "))
	check("form", strings.Join(s.Forms, " "))
	check("text", s.Text)
	return where
}

var reDigits = regexp.MustCompile(`[0-9]+`)

// Signature is a 64-bit simhash of the page's evidence. Digits are folded so
// timestamps, build ids and tokens do not matter; structure (headers,
// assets, forms) weighs more than visible text. Pages of one product on
// different hosts get signatures a few bits apart; see SimilarDistance.
func (s *Page) Signature() uint64 {
	var v [64]int
	add := func(kind, feature string, weight int) {
		h := fnv.New64a()
		h.Write([]byte(kind))
		h.Write([]byte(reDigits.ReplaceAllString(strings.ToLower(feature), "0")))
		x := h.Sum64()
		for i := 0; i < 64; i++ {
			if x&(1<<uint(i)) != 0 {
				v[i] += weight
			} else {
				v[i] -= weight
			}
		}
	}
	add("status", s.Status, 3)
	for k, val := range s.Headers {
		add("header", k+": "+val, 3)
	}
	for _, list := range [][]string{s.Cookies, s.Scripts, s.Styles, s.InlineHints, s.Comments, s.Forms} {
		for _, f := range list {
			if i := strings.IndexByte(f, '?'); i >= 0 {
				f = f[:i]
			}
			add("struct", f, 3)
		}
	}
	add("generator", s.Generator, 3)
	for _, w := range strings.Fields(s.Title) {
		add("title", w, 2)
	}
	for _, w := range strings.Fields(s.Text) {
		add("text", w, 1)
	}
	var sig uint64
	for i := 0; i < 64; i++ {
		if v[i] > 0 {
			sig |= 1 << uint(i)
		}
	}
	return sig
}
