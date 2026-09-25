package judge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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

// mock is a Provider answering from a table keyed by question kind and the
// product named in backticks; it records the question keys of each call.
type mock struct {
	mu        sync.Mutex
	delay     time.Duration
	calls     int64
	requests  [][]string
	fail      bool
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
	s := q.Instructions
	if i := strings.Index(s, "`"); i >= 0 {
		if j := strings.Index(s[i+1:], "`"); j >= 0 {
			return s[i+1 : i+1+j]
		}
	}
	return ""
}

func (m *mock) ID() string { return "mock" }

func (m *mock) Judge(ctx context.Context, state interface{}, questions map[string]Question) (map[string]Answer, error) {
	atomic.AddInt64(&m.calls, 1)
	time.Sleep(m.delay)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return nil, errors.New("provider down")
	}
	m.lastState, _ = state.(map[string]interface{})
	answers := map[string]Answer{}
	var keys []string
	for k, q := range questions {
		keys = append(keys, k)
		name := named(q)
		switch {
		case strings.HasPrefix(k, "is_"):
			answers[k] = Answer{Yes: m.present[name]}
		case strings.HasPrefix(k, "layer_"):
			answers[k] = Answer{Choice: string(m.layer[name]), Confidence: 0.9}
		case k == "primary":
			answers[k] = Answer{Choice: m.primary, Confidence: 0.9}
		case k == "page_kind":
			answers[k] = Answer{Choice: "login", Confidence: 0.9}
		case k == "generic":
			answers[k] = Answer{Yes: 0.9}
		case k == "version":
			answers[k] = Answer{Choice: "2.401.3", Confidence: m.versionP}
		default:
			answers[k] = Answer{Yes: 0.7}
		}
	}
	sort.Strings(keys)
	m.requests = append(m.requests, keys)
	return answers, nil
}

// client keeps the old test shape: a Judge over the mock.
func (m *mock) client(t *testing.T) (*Judge, func()) { return New(m), func() {} }

func testFrames() common.Frameworks {
	fs := common.Frameworks{}
	fs.Add(common.NewFramework("nginx", common.FrameFromFingers))
	fs.Add(common.NewFramework("wordpress", common.FrameFromGoby))
	fs.Add(common.NewFramework("jenkins", common.FrameFromFingerprintHub))
	fs.Add(common.NewFramework("apache-tomcat", common.FrameFromFingers))
	fs.Add(common.NewFramework("apache tomcat", common.FrameFromWappalyzer))
	return fs
}

func refine(t *testing.T, c *Judge, frames common.Frameworks) (*Page, error) {
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
	if !Is(frames["wordpress"], Rejected) {
		t.Errorf("text-only wordpress not rejected: %v", frames["wordpress"].Tags)
	}
	if nginx := frames["nginx"]; Is(nginx, Rejected) || LayerOf(nginx) != LayerServer {
		t.Errorf("nginx from the Server header must be kept: %v", nginx.Tags)
	}
	if Is(frames["apache tomcat"], Duplicate) == Is(frames["apache-tomcat"], Duplicate) {
		t.Errorf("exactly one tomcat spelling must be a dup")
	}
	j := frames["jenkins"]
	if !Is(j, Primary) || j.Version != "2.401.3" || PrimaryOf(frames) != j {
		t.Errorf("jenkins primary/version: %v %q", j.Tags, j.Version)
	}
	if f := frames["prototype"]; f == nil || !Is(f, Recalled) || !f.IsGuess() {
		t.Errorf("confirmed recall not added: %+v", f)
	}
	if got := Accepted(frames); len(got) != 4 { // nginx, tomcat, jenkins, prototype
		t.Errorf("accepted: %v", got)
	}
	if p.Kind != KindLogin || !p.Generic {
		t.Errorf("page: %q %v", p.Kind, p.Generic)
	}
	// Jenkins is both a rule hit and a recall name: asked once. 5 products x 2 + primary + page_kind + generic.
	if len(m.requests) != 2 || len(m.requests[0]) != 13 || strings.Join(m.requests[1], ",") != "version" {
		t.Errorf("requests: %v", m.requests)
	}
	if _, ok := m.lastState["version_strings"]; !ok {
		t.Errorf("version strings not in the state: %v", m.lastState)
	}
	if c.Requests != 2 {
		t.Errorf("requests: %d", c.Requests)
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
	m.fail = true
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
	r.Add("honeypot", Binary("Is this a honeypot?"), func(a Answer) { custom = a.Yes })
	if err := r.Ask(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if strings.Join(m.requests[0], ",") != "generic,honeypot,page_kind" || p.Kind != KindLogin || custom != 0.7 {
		t.Fatalf("requests=%v kind=%q custom=%v", m.requests, p.Kind, custom)
	}
	if err := p.Round().Ask(context.Background(), c); err != nil || m.calls != 1 {
		t.Fatalf("empty round sent a request: %v %d", err, m.calls)
	}
	r = p.Round()
	r.Add("x", Binary("?"), nil)
	r.Add("x", Binary("?"), nil)
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
	if v, ok := c.Get("a", 0x1); !ok || string(v) != "1" {
		t.Fatal("signature 1 bit away missed")
	}
	if _, ok := c.Get("a", 0x3); ok {
		t.Fatal("signature 2 bits away matched")
	}
}

// The same product page on another host (other token, date, host name) reuses
// the answers; a different page does not.
func TestSimilarPagesShareAnswers(t *testing.T) {
	m := newMock()
	c, stop := m.client(t)
	defer stop()
	c.Cache = NewMemoryCache(16)
	// Same page on another host: other session, build number and date.
	page := func(build, date string) string {
		return strings.Replace(jenkinsRaw, "We moved here from WordPress.", "We moved here from WordPress. Build "+build+", "+date+".", 1)
	}
	orig, variant := page("101", "2026-09-24"), page("2087", "2025-01-03")
	a, _ := NewPage([]byte(orig))
	b, _ := NewPage([]byte(variant))
	other, _ := NewPage([]byte("HTTP/1.1 200 OK\r\nServer: Apache\r\n\r\n<title>Index of /</title><a href=\"a.txt\">a.txt</a>"))
	if !Similar(a.Signature(), b.Signature()) || Similar(a.Signature(), other.Signature()) {
		t.Fatalf("signatures: %x %x %x", a.Signature(), b.Signature(), other.Signature())
	}
	for _, raw := range []string{orig, variant} {
		p, _ := NewPage([]byte(raw))
		r := p.Round()
		Classify(r)
		if err := r.Ask(context.Background(), c); err != nil || p.Kind != KindLogin {
			t.Fatalf("kind %q err %v", p.Kind, err)
		}
	}
	if m.calls != 1 || c.CacheHits != 1 {
		t.Fatalf("similar page not served from cache: calls=%d hits=%d", m.calls, c.CacheHits)
	}
}

// A provider that reports a calibration sets the Judge's thresholds.
type calibrated struct{ mock }

func (*calibrated) Calibration() (float64, float64) { return 0.7, 0.8 }

func TestCalibration(t *testing.T) {
	if j := New(newMock()); j.Threshold != 0.5 || j.VersionConfidence != 0.9 {
		t.Fatalf("defaults: %v %v", j.Threshold, j.VersionConfidence)
	}
	if j := New(&calibrated{}); j.Threshold != 0.7 || j.VersionConfidence != 0.8 {
		t.Fatalf("calibration: %v %v", j.Threshold, j.VersionConfidence)
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
	m.primary = noneOfThem
	c, stop := m.client(t)
	defer stop()
	frames := common.Frameworks{}
	frames.Add(common.NewFramework("nginx", common.FrameFromFingers))
	if _, err := refine(t, c, frames); err != nil {
		t.Fatal(err)
	}
	if PrimaryOf(frames) != nil || frames["nginx"].Version == "" {
		t.Fatalf("subject version not asked: %+v", frames["nginx"])
	}
}

// Refine on frames it already judged sends nothing: Verify skips judged hits,
// Classify is answered by the cache, and the version is already set.
func TestRefineIsIdempotent(t *testing.T) {
	m := newMock()
	c, stop := m.client(t)
	defer stop()
	frames := testFrames()
	for i := 0; i < 2; i++ {
		if _, err := refine(t, c, frames); err != nil {
			t.Fatal(err)
		}
	}
	if m.calls != 2 || !Is(frames["wordpress"], Rejected) || len(frames["wordpress"].Tags) != len(testFrames()["wordpress"].Tags)+2 {
		t.Fatalf("calls=%d wordpress=%v requests=%v", m.calls, frames["wordpress"].Tags, m.requests)
	}
}

// Many workers judging the same page at once (a scan hitting one product
// everywhere) cost one request.
func TestConcurrentSimilarPagesMerge(t *testing.T) {
	m := newMock()
	m.delay = 100 * time.Millisecond
	c, stop := m.client(t)
	defer stop()
	var wg sync.WaitGroup
	kinds := make([]Kind, 20)
	for i := range kinds {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			raw := strings.Replace(jenkinsRaw, "JSESSIONID.1=x", fmt.Sprintf("JSESSIONID.1=%d", i), 1)
			p, _ := NewPage([]byte(raw))
			r := p.Round()
			Classify(r)
			if err := r.Ask(context.Background(), c); err != nil {
				t.Error(err)
			}
			kinds[i] = p.Kind
		}(i)
	}
	wg.Wait()
	for i, k := range kinds {
		if k != KindLogin {
			t.Fatalf("worker %d: kind %q", i, k)
		}
	}
	if m.calls != 1 || c.CacheHits != 19 {
		t.Fatalf("calls=%d hits=%d", m.calls, c.CacheHits)
	}
}

// A round partly answered by the cache sends only the rest.
func TestPartialCacheHit(t *testing.T) {
	m := newMock()
	c, stop := m.client(t)
	defer stop()
	p, _ := NewPage([]byte(jenkinsRaw))
	r := p.Round()
	Classify(r)
	if err := r.Ask(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	p, _ = NewPage([]byte(jenkinsRaw))
	r = p.Round()
	Classify(r)
	r.Add("extra", Binary("Is this page served over a CDN?"), nil)
	if err := r.Ask(context.Background(), c); err != nil || p.Kind != KindLogin {
		t.Fatalf("err %v kind %q", err, p.Kind)
	}
	if len(m.requests) != 2 || strings.Join(m.requests[1], ",") != "extra" {
		t.Fatalf("requests: %v", m.requests)
	}
}

// Without a primary, the only server is the subject even next to an OS.
func TestVersionSubjectPrefersServer(t *testing.T) {
	frames := common.Frameworks{}
	for name, l := range map[string]Layer{"apache": LayerServer, "ubuntu": LayerDevice} {
		f := common.NewFramework(name, common.FrameFromFingers)
		setLayer(f, l)
		frames.Add(f)
	}
	if f := subject(frames); f == nil || f.Name != "apache" {
		t.Fatalf("subject: %+v", f)
	}
}

// Sparse pages with common headers must not look alike: CJK text counts, and
// similar pages must share a title.
func TestUnrelatedSparsePagesDoNotShare(t *testing.T) {
	head := "HTTP/1.1 200 OK\r\nServer: nginx\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<script src=\"/js/jquery.min.js\"></script>"
	a, _ := NewPage([]byte(head + "<title>职业规划咨询</title><p>生涯规划师与高考志愿规划，帮助学生找到方向</p>"))
	b, _ := NewPage([]byte(head + "<title>官方网站</title><p>在线娱乐平台，注册即送体验金</p>"))
	if Similar(a.Signature(), b.Signature()) && a.similarityScope() == b.similarityScope() {
		t.Fatalf("unrelated pages share answers: %x %x", a.Signature(), b.Signature())
	}
}
