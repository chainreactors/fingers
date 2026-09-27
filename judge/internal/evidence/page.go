package evidence

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Page is the compact, named view of one HTTP response that providers judge
// (serialized as the request state). A provider only judges the evidence it
// is given and loses accuracy on large states full of irrelevant detail, so
// the fields below are the ones that carry fingerprint signal.
type Page struct {
	Status      string            `json:"status"`
	Headers     map[string]string `json:"headers,omitempty"`
	Cookies     []string          `json:"cookie_names,omitempty"`
	Title       string            `json:"title,omitempty"`
	Generator   string            `json:"meta_generator,omitempty"`
	Description string            `json:"meta_description,omitempty"`
	Scripts     []string          `json:"script_src,omitempty"`
	Styles      []string          `json:"stylesheet_href,omitempty"`
	InlineHints []string          `json:"inline_script_starts,omitempty"` // first chars of inline scripts, e.g. "(function(w,d,s,l,i){ ... GTM"
	Comments    []string          `json:"html_comments,omitempty"`
	Forms       []string          `json:"form_inputs,omitempty"`
	Text        string            `json:"visible_text,omitempty"`

	Raw    []byte      `json:"-"`
	Header http.Header `json:"-"`
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

	reDescription = regexp.MustCompile(`(?is)<meta[^>]+name=["']description["'][^>]*content=["']([^"']+)|<meta[^>]+content=["']([^"']+)["'][^>]*name=["']description["']`)
	reScript      = regexp.MustCompile(`(?is)<script[^>]+src=["']([^"']+)`)
	reStyle       = regexp.MustCompile(`(?is)<link[^>]+rel=["']?stylesheet[^>]*href=["']([^"']+)|<link[^>]+href=["']([^"']+)["'][^>]*rel=["']?stylesheet`)
	reInline      = regexp.MustCompile(`(?is)<script(?:\s[^>]*)?>(.*?)</script>`)
	reComment     = regexp.MustCompile(`(?s)<!--(.*?)-->`)
	reInput       = regexp.MustCompile(`(?is)<input[^>]*>`)
	reAttrName    = regexp.MustCompile(`(?is)\b(?:name|id)=["']([^"']+)`)
	reAttrType    = regexp.MustCompile(`(?is)\btype=["']([^"']+)`)
	reDropBlock   = regexp.MustCompile(`(?is)<(script|style|noscript)[^>]*>.*?</(script|style|noscript)>`)
	reTag         = regexp.MustCompile(`(?s)<[^>]+>`)
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
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	s := &Page{Status: resp.Status, Headers: map[string]string{}, Raw: raw, Header: resp.Header.Clone()}
	for k, vs := range resp.Header {
		if skipHeaders[k] || strings.HasPrefix(k, "X-Crawler-") || len(vs) == 0 {
			continue
		}
		s.Headers[k] = Truncate(strings.Join(vs, ", "), maxHeaderValue)
	}
	for _, c := range resp.Cookies() {
		s.Cookies = append(s.Cookies, c.Name)
	}
	html := string(body)
	if m := Title.FindStringSubmatch(html); m != nil {
		s.Title = clean(m[1])
	}
	if m := Generator.FindStringSubmatch(html); m != nil {
		s.Generator = m[1] + m[2]
	}
	if m := reDescription.FindStringSubmatch(html); m != nil {
		s.Description = Truncate(clean(m[1]+m[2]), 300)
	}
	for _, m := range reScript.FindAllStringSubmatch(html, 8) {
		s.Scripts = append(s.Scripts, m[1])
	}
	for _, m := range reStyle.FindAllStringSubmatch(html, 8) {
		s.Styles = append(s.Styles, m[1]+m[2])
	}
	for _, m := range reInline.FindAllStringSubmatch(html, -1) {
		if code := clean(m[1]); len(code) > 20 && len(s.InlineHints) < 5 {
			s.InlineHints = append(s.InlineHints, Truncate(code, 100))
		}
	}
	for _, m := range reComment.FindAllStringSubmatch(html, -1) {
		if c := clean(m[1]); len(c) > 3 && len(s.Comments) < 5 && !strings.HasPrefix(c, "[if") {
			s.Comments = append(s.Comments, Truncate(c, 80))
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
	s.Text = Truncate(text, maxText)
	return s, nil
}

func clean(s string) string { return Clean(s) }

func Truncate(s string, max int) string {
	if utf8.RuneCountInString(s) <= max {
		return s
	}
	return string([]rune(s)[:max]) + "…"
}
