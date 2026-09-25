package jev

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/chainreactors/fingers/common"
)

const jenkinsRaw = "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nX-Jenkins: 2.401.3\r\nSet-Cookie: JSESSIONID.1=x; Path=/\r\nContent-Type: text/html\r\n\r\n" +
	`<html><head><title>Sign in [Jenkins]</title><script src="/static/prototype.js"></script></head>` +
	`<body><script>var x=1;</script><p>We moved here from WordPress.</p>` +
	`<input name="j_username" type="text"><input name="j_password" type="password"></body></html>`

func TestNewPage(t *testing.T) {
	s, err := NewPage([]byte(jenkinsRaw))
	if err != nil {
		t.Fatal(err)
	}
	if s.Title != "Sign in [Jenkins]" || s.Headers["X-Jenkins"] != "2.401.3" {
		t.Fatalf("title/header: %+v", s)
	}
	if len(s.Cookies) != 1 || len(s.Scripts) != 1 || len(s.Forms) != 2 {
		t.Fatalf("cookies/scripts/forms: %+v", s)
	}
	if got := extractVersions([]byte(jenkinsRaw), 5); len(got) != 2 || got[0].Value != "1.24.0" || got[1].Value != "2.401.3" {
		t.Fatalf("versions: %v", got)
	}
	if got := NewRetriever([]string{"jenkins", "oa", "tomcat"}).Find(s.Haystack(), 5); len(got) != 1 || got[0] != "jenkins" {
		t.Fatalf("retriever: %v", got)
	}
	if b, _ := json.Marshal(s); strings.Contains(string(b), "Kind") || strings.Contains(string(b), "Generic") {
		t.Fatalf("conclusions leak into the state: %s", b)
	}
}

// mock answers every question from a table keyed by question kind and the
// product named in backticks, and records the question keys of each request.
type mock struct {
	calls     int64
	requests  [][]string
	status    int
	versionP  float64
	present   map[string]float64
	layer     map[string]Layer
	primary   string
	lastState map[string]interface{}
}

func newMock() *mock {
	return &mock{
		versionP: 0.95,
		present:  map[string]float64{"nginx": 0.1, "wordpress": 0.05, "jenkins": 0.97, "apache tomcat": 0.8, "Prototype": 0.9},
		layer: map[string]Layer{"nginx": LayerServer, "wordpress": LayerNotPresent, "jenkins": LayerApplication,
			"apache tomcat": LayerServer, "Prototype": LayerFrontend},
		primary: "jenkins",
	}
}

func named(q Question) string {
	s, _ := q.Instructions.(string)
	if i := strings.Index(s, "`"); i >= 0 {
		if j := strings.Index(s[i+1:], "`"); j >= 0 {
			return s[i+1 : i+1+j]
		}
	}
	return ""
}

func (m *mock) client(t *testing.T) (*Client, func()) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&m.calls, 1)
		if m.status != 0 {
			w.WriteHeader(m.status)
			return
		}
		var req request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode: %v", err)
		}
		m.lastState, _ = req.State.(map[string]interface{})
		answers := map[string]Answer{}
		var keys []string
		for k, q := range req.Questions {
			keys = append(keys, k)
			name := named(q)
			switch {
			case strings.HasPrefix(k, "is_"):
				answers[k] = Answer{Type: "noul", Noul: m.present[name]}
			case strings.HasPrefix(k, "layer_"):
				answers[k] = Answer{Type: "choice", Choice: string(m.layer[name]), Confidence: 0.9}
			case k == "primary":
				answers[k] = Answer{Type: "choice", Choice: m.primary, Confidence: 0.9}
			case k == "page_kind":
				answers[k] = Answer{Type: "choice", Choice: "login", Confidence: 0.9}
			case k == "generic":
				answers[k] = Answer{Type: "noul", Noul: 0.9}
			case k == "version":
				answers[k] = Answer{Type: "choice", Choice: "2.401.3", Confidence: m.versionP}
			default:
				answers[k] = Answer{Type: "noul", Noul: 0.7}
			}
		}
		sort.Strings(keys)
		m.requests = append(m.requests, keys)
		json.NewEncoder(w).Encode(Response{Model: DefaultModel, Answers: answers, Usage: Usage{InputTokens: 100}})
	}))
	c, _ := NewClient("k")
	c.Endpoint = srv.URL
	c.MaxRetries = 0
	return c, srv.Close
}

func testFrames() common.Frameworks {
	fs := common.Frameworks{}
	fs.Add(common.NewFramework("nginx", common.FrameFromFingers))
	fs.Add(common.NewFramework("wordpress", common.FrameFromGoby))
	fs.Add(common.NewFramework("jenkins", common.FrameFromFingerprintHub))
	fs.Add(common.NewFramework("apache-tomcat", common.FrameFromFingers))
	fs.Add(common.NewFramework("apache tomcat", common.FrameFromWappalyzer))
	return fs
}

func refine(t *testing.T, c *Client, frames common.Frameworks) (*Page, error) {
	p, err := NewPage([]byte(jenkinsRaw))
	if err != nil {
		t.Fatal(err)
	}
	return p, Refine(context.Background(), c, p, frames, []string{"Jenkins", "Prototype"})
}

func TestRefine(t *testing.T) {
	m := newMock()
	c, stop := m.client(t)
	defer stop()
	frames := testFrames()
	p, err := refine(t, c, frames)
	if err != nil {
		t.Fatal(err)
	}
	if !frames["wordpress"].HasTag(TagRejected) {
		t.Errorf("text-only wordpress not rejected: %v", frames["wordpress"].Tags)
	}
	if nginx := frames["nginx"]; nginx.HasTag(TagRejected) || !nginx.HasTag(TagLayer+string(LayerServer)) {
		t.Errorf("nginx from the Server header must be kept: %v", nginx.Tags)
	}
	if frames["apache tomcat"].HasTag(TagDup) == frames["apache-tomcat"].HasTag(TagDup) {
		t.Errorf("exactly one tomcat spelling must be a dup")
	}
	j := frames["jenkins"]
	if !j.HasTag(TagPrimary) || j.Version != "2.401.3" || Primary(frames) != j {
		t.Errorf("jenkins primary/version: %v %q", j.Tags, j.Version)
	}
	if f := frames["prototype"]; f == nil || !f.HasTag(TagRecall) || !f.IsGuess() {
		t.Errorf("confirmed recall not added: %+v", f)
	}
	if got := Accepted(frames); len(got) != 4 { // nginx, tomcat, jenkins, prototype
		t.Errorf("accepted: %v", got)
	}
	if p.Kind != "login" || !p.Generic {
		t.Errorf("page: %q %v", p.Kind, p.Generic)
	}
	// Jenkins is both a rule hit and a recall name: asked once. 5 products x 2 + primary + page_kind + generic.
	if len(m.requests) != 2 || len(m.requests[0]) != 13 || strings.Join(m.requests[1], ",") != "version" {
		t.Errorf("requests: %v", m.requests)
	}
	if _, ok := m.lastState["version_strings"]; !ok {
		t.Errorf("version strings not in the state: %v", m.lastState)
	}
	if c.Requests != 2 || c.InputTokens != 200 {
		t.Errorf("usage: %d %d", c.Requests, c.InputTokens)
	}
}

func TestVersionNeedsConfidence(t *testing.T) {
	m := newMock()
	m.versionP = 0.6
	c, stop := m.client(t)
	defer stop()
	frames := testFrames()
	if _, err := refine(t, c, frames); err != nil {
		t.Fatal(err)
	}
	if v := frames["jenkins"].Version; v != "" {
		t.Fatalf("low-confidence version written: %q", v)
	}
}

func TestFailedRoundLeavesFrames(t *testing.T) {
	m := newMock()
	m.status = 500
	c, stop := m.client(t)
	defer stop()
	frames := testFrames()
	before, _ := json.Marshal(frames)
	p, err := refine(t, c, frames)
	if err == nil {
		t.Fatal("expected error")
	}
	if after, _ := json.Marshal(frames); string(after) != string(before) || p.Kind != "" {
		t.Fatalf("frames changed on failure:\n%s\n%s", before, after)
	}
}

func TestCache(t *testing.T) {
	m := newMock()
	c, stop := m.client(t)
	defer stop()
	c.Cache = NewMemoryCache(16)
	for i := 0; i < 2; i++ {
		frames := testFrames()
		if _, err := refine(t, c, frames); err != nil {
			t.Fatal(err)
		}
		if frames["jenkins"].Version != "2.401.3" {
			t.Fatalf("run %d: cached answers not applied", i)
		}
	}
	if m.calls != 2 || c.CacheHits != 2 {
		t.Fatalf("calls=%d hits=%d", m.calls, c.CacheHits)
	}
}

func TestClassifyAlone(t *testing.T) {
	m := newMock()
	c, stop := m.client(t)
	defer stop()
	p, _ := NewPage([]byte(jenkinsRaw))
	r := p.Round()
	Classify(r)
	var custom float64
	r.Add("honeypot", Noul("Is this a honeypot?"), func(a Answer) { custom = a.Noul })
	if err := r.Ask(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if strings.Join(m.requests[0], ",") != "generic,honeypot,page_kind" || p.Kind != "login" || custom != 0.7 {
		t.Fatalf("requests=%v kind=%q custom=%v", m.requests, p.Kind, custom)
	}
	if err := p.Round().Ask(context.Background(), c); err != nil || m.calls != 1 {
		t.Fatalf("empty round sent a request: %v %d", err, m.calls)
	}
	r = p.Round()
	r.Add("x", Noul("?"), nil)
	r.Add("x", Noul("?"), nil)
	if err := r.Ask(context.Background(), c); err == nil {
		t.Fatal("duplicate key accepted")
	}
}

func TestMemoryCacheEvicts(t *testing.T) {
	c := NewMemoryCache(2)
	c.Put("a", 0, []byte("1"))
	c.Put("b", 0, []byte("2"))
	c.Get("a", 0)
	c.Put("c", 0, []byte("3"))
	if _, ok := c.Get("b", 0); ok {
		t.Fatal("least recently used entry kept")
	}
	if v, ok := c.Get("a", 0); !ok || string(v) != "1" {
		t.Fatal("recent entry evicted")
	}
	if _, ok := c.Get("a", 0xff); ok {
		t.Fatal("signature 8 bits away matched")
	}
	if v, ok := c.Get("a", 0x3); !ok || string(v) != "1" {
		t.Fatal("signature 2 bits away missed")
	}
}

// The same product page on another host (other token, date, host name) reuses
// the answers; a different page does not.
func TestSimilarPagesShareAnswers(t *testing.T) {
	m := newMock()
	c, stop := m.client(t)
	defer stop()
	c.Cache = NewMemoryCache(16)
	variant := strings.NewReplacer("JSESSIONID.1=x", "JSESSIONID.1=9f8e7d", "Sign in [Jenkins]", "Sign in [Jenkins]",
		"We moved here from WordPress.", "We moved here from WordPress on 2026-09-24.").Replace(jenkinsRaw)
	a, _ := NewPage([]byte(jenkinsRaw))
	b, _ := NewPage([]byte(variant))
	other, _ := NewPage([]byte("HTTP/1.1 200 OK\r\nServer: Apache\r\n\r\n<title>Index of /</title><a href=\"a.txt\">a.txt</a>"))
	if !Similar(a.Signature(), b.Signature()) || Similar(a.Signature(), other.Signature()) {
		t.Fatalf("signatures: %x %x %x", a.Signature(), b.Signature(), other.Signature())
	}
	for _, raw := range []string{jenkinsRaw, variant} {
		p, _ := NewPage([]byte(raw))
		r := p.Round()
		Classify(r)
		if err := r.Ask(context.Background(), c); err != nil || p.Kind != "login" {
			t.Fatalf("kind %q err %v", p.Kind, err)
		}
	}
	if m.calls != 1 || c.CacheHits != 1 {
		t.Fatalf("similar page not served from cache: calls=%d hits=%d", m.calls, c.CacheHits)
	}
}

func TestAskRetriesOverload(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") != "Bearer k" {
			t.Errorf("auth header: %q", r.Header.Get("Authorization"))
		}
		if calls == 1 {
			w.WriteHeader(529)
			return
		}
		var req request
		json.NewDecoder(r.Body).Decode(&req)
		if req.Model != DefaultModel || req.Questions["q"].Type != "noul" {
			t.Errorf("request: %+v", req)
		}
		w.Write([]byte(`{"model":"jev-1.13.0","answers":{"q":{"type":"noul","noul":0.9}},"usage":{"input_tokens":10,"output_tokens":1}}`))
	}))
	defer srv.Close()

	c, _ := NewClient("k")
	c.Endpoint = srv.URL
	resp, err := c.Ask(context.Background(), "state", map[string]Question{"q": Noul("?")})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 || resp.Answers["q"].Noul != 0.9 {
		t.Fatalf("calls=%d resp=%+v", calls, resp)
	}
}

func TestExtractVersionsPrefixes(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\n\r\n<meta content=\"Discuz! X3.4\"><title>V8.1SP2</title> 10.0.0.5 jquery.min.js?ver=3.7.1"
	var got []string
	for _, c := range extractVersions([]byte(raw), 10) {
		got = append(got, c.Value)
	}
	if strings.Join(got, ",") != "3.4,8.1,3.7.1" {
		t.Fatalf("got %v", got)
	}
}

func TestRetrieverWordBoundary(t *testing.T) {
	r := NewRetriever([]string{"acti", "jenkins", "泛微"})
	if got := r.Find("take action now", 5); len(got) != 0 {
		t.Fatalf("substring matched: %v", got)
	}
	if got := r.Find("sign in [jenkins] 泛微oa", 5); len(got) != 2 {
		t.Fatalf("got %v", got)
	}
}

func TestRankVersions(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\n\r\n<link href=\"/wp-content/plugins/x/a.css?ver=7.0.3\">"
	for i := 0; i < 15; i++ {
		raw += fmt.Sprintf(`<link href="/wp-content/plugins/p%d/a.css?ver=1.%d.0">`, i, i)
	}
	raw += `<meta name="generator" content="WordPress 7.0.3" /><meta name="Generator" content="Drupal 10 (https://www.drupal.org)" />`
	cands := extractVersions([]byte(raw), 40)
	got := rankVersions(cands, "wordpress", 3)
	if got[0].Value != "7.0.3" || !strings.Contains(got[0].Context, "generator") {
		t.Fatalf("wordpress generator not ranked first: %+v", got)
	}
	var drupal bool
	for _, c := range cands {
		drupal = drupal || c.Value == "10"
	}
	if !drupal {
		t.Fatalf("major-only generator version missing: %+v", cands)
	}
}

func TestNormalizeName(t *testing.T) {
	same := [][]string{{"Apache HTTP Server", "apache-http", "apache-web-server", "Apache"}, {"Discuz! X", "discuz"}, {"Apache-Tomcat", "apache tomcat"}, {"泛微 OA", "泛微"}}
	for _, names := range same {
		for _, n := range names[1:] {
			if NormalizeName(n) != NormalizeName(names[0]) {
				t.Errorf("%q and %q not folded: %q %q", names[0], n, NormalizeName(names[0]), NormalizeName(n))
			}
		}
	}
	for _, pair := range [][2]string{{"lighttpd", "lig"}, {"Apache Tomcat", "Apache"}, {"nginx", "ngin"}} {
		if NormalizeName(pair[0]) == NormalizeName(pair[1]) {
			t.Errorf("%q and %q folded", pair[0], pair[1])
		}
	}
}

// A server's own page has no primary application; the only server is the subject.
func TestVersionWithoutPrimary(t *testing.T) {
	m := newMock()
	m.primary = NoneOfThem
	c, stop := m.client(t)
	defer stop()
	frames := common.Frameworks{}
	frames.Add(common.NewFramework("nginx", common.FrameFromFingers))
	if _, err := refine(t, c, frames); err != nil {
		t.Fatal(err)
	}
	if Primary(frames) != nil || frames["nginx"].Version == "" {
		t.Fatalf("subject version not asked: %+v", frames["nginx"])
	}
}
