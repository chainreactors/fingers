package judge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/bits"
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
	if got := NewRetriever([]string{"jenkins", "oa", "tomcat"}).Find(s.haystack(), 5); len(got) != 1 || got[0] != "jenkins" {
		t.Fatalf("retriever: %v", got)
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
	layer     map[string]string
	versions  map[string]string // product -> version picked, if among the options
	primary   string
	lastState map[string]interface{}
}

func newMock() *mock {
	return &mock{
		versionP: 0.95,
		present:  map[string]float64{"nginx": 0.1, "wordpress": 0.05, "jenkins": 0.97, "apache tomcat": 0.8, "prototype": 0.9},
		versions: map[string]string{"jenkins": "2.401.3", "nginx": "1.24.0"},
		layer: map[string]string{"nginx": LayerServer, "wordpress": LayerNotPresent, "jenkins": LayerApplication,
			"apache tomcat": LayerServer, "prototype": LayerFrontend},
		primary: "jenkins",
	}
}

// named is the first product named in backticks, skipping evidence names.
func named(q Question) string {
	parts := strings.Split(q.Instructions, "`")
	for i := 1; i < len(parts); i += 2 {
		if parts[i] != "version_strings" {
			return parts[i]
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
		name := strings.ToLower(named(q))
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
		case strings.HasPrefix(k, "version_"):
			choice := notStated
			if v, ok := m.versions[name]; ok {
				if _, offered := q.Options[v]; offered {
					choice = v
				}
			}
			answers[k] = Answer{Choice: choice, Confidence: m.versionP}
		default:
			answers[k] = Answer{Yes: 0.7}
		}
	}
	sort.Strings(keys)
	m.requests = append(m.requests, keys)
	return answers, nil
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

// newJudge is a Judge over m that recalls Jenkins and Prototype by name.
func newJudge(m *mock) *Judge {
	j := New(m)
	j.Known = NewRetriever([]string{"Jenkins", "Prototype"})
	return j
}

// bodyRaw states versions only in the body, so the provider has to pick them.
const bodyRaw = "HTTP/1.1 200 OK\r\nServer: nginx\r\nSet-Cookie: JSESSIONID.1=x; Path=/\r\n\r\n" +
	`<html><head><title>Sign in [Jenkins]</title><script src="/static/prototype.js"></script></head>` +
	`<body><p>We moved here from WordPress.</p><footer>Jenkins 2.401.3, nginx 1.24.0</footer></body></html>`

func TestRefine(t *testing.T) {
	m := newMock()
	j := newJudge(m)
	all, err := j.Inspect(context.Background(), []byte(jenkinsRaw), testFrames())
	if err != nil {
		t.Fatal(err)
	}
	if w := all["wordpress"]; w.Judge == nil || !w.Judge.Rejected {
		t.Errorf("text-only wordpress not rejected: %+v", w.Judge)
	}
	if nginx := all["nginx"].Judge; nginx.Rejected || nginx.Layer != LayerServer || nginx.Confidence != 0.1 {
		t.Errorf("nginx from the Server header must be kept: %+v", nginx)
	}
	if all["apache tomcat"].Judge.Duplicate == all["apache-tomcat"].Judge.Duplicate {
		t.Errorf("exactly one tomcat spelling must be a dup")
	}
	if p := all["prototype"]; p == nil || !p.Judge.Recalled || !p.IsGuess() {
		t.Errorf("confirmed recall not added: %+v", p)
	}
	// Jenkins is both a rule hit and a recall name: asked once. 5 products x 2 + primary + page_kind + generic.
	if len(m.requests) != 1 || len(m.requests[0]) != 13 {
		t.Fatalf("requests: %v", m.requests)
	}

	accepted, err := j.Refine(context.Background(), []byte(jenkinsRaw), testFrames())
	if err != nil {
		t.Fatal(err)
	}
	if len(accepted) != 4 { // nginx, tomcat, jenkins, prototype
		t.Errorf("accepted: %v", accepted)
	}
	jenkins := accepted["jenkins"]
	if !jenkins.Judge.Primary || accepted.Primary() != jenkins {
		t.Errorf("jenkins primary: %+v", jenkins.Judge)
	}
	// Both versions are bound by name in the headers: taken without asking,
	// and not offered to the products they do not name.
	if jenkins.Version != "2.401.3" || accepted["nginx"].Version != "1.24.0" || accepted["prototype"].Version != "" {
		t.Errorf("versions: jenkins %q nginx %q prototype %q", jenkins.Version, accepted["nginx"].Version, accepted["prototype"].Version)
	}
	if len(m.requests) != 1 || j.CacheHits != 1 {
		t.Errorf("header versions or cached verdicts were asked again: %v hits=%d", m.requests, j.CacheHits)
	}
	if kind, generic, err := j.Classify(context.Background(), []byte(jenkinsRaw)); err != nil || kind != KindLogin || !generic || len(m.requests) != 1 {
		t.Errorf("classify after refine: %q %v %v, requests %v", kind, generic, err, m.requests)
	}
}

// Versions stated only in the body are picked by the provider, all kept
// products in one request, each from its own candidates.
func TestRefineVersionsEveryProduct(t *testing.T) {
	m := newMock()
	j := newJudge(m)
	accepted, err := j.Refine(context.Background(), []byte(bodyRaw), testFrames())
	if err != nil {
		t.Fatal(err)
	}
	if accepted["jenkins"].Version != "2.401.3" || accepted["nginx"].Version != "1.24.0" {
		t.Fatalf("versions: jenkins %q nginx %q", accepted["jenkins"].Version, accepted["nginx"].Version)
	}
	// jenkins (primary), apache tomcat and nginx (servers), prototype (frontend).
	if len(m.requests) != 2 || strings.Join(m.requests[1], ",") != "version_0,version_1,version_2,version_3" {
		t.Fatalf("requests: %v", m.requests)
	}
	if _, ok := m.lastState["version_strings"]; !ok {
		t.Errorf("version strings not in the state: %v", m.lastState)
	}
}

// One version string occurring once goes to one product only.
func TestVersionGoesToOneProduct(t *testing.T) {
	m := newMock()
	m.versions = map[string]string{"jenkins": "2.401.3", "nginx": "2.401.3"}
	raw := strings.Replace(bodyRaw, "Jenkins 2.401.3, nginx 1.24.0", "Jenkins 2.401.3", 1)
	accepted, err := newJudge(m).Refine(context.Background(), []byte(raw), testFrames())
	if err != nil {
		t.Fatal(err)
	}
	if accepted["jenkins"].Version != "2.401.3" || accepted["nginx"].Version != "" {
		t.Fatalf("versions: jenkins %q nginx %q", accepted["jenkins"].Version, accepted["nginx"].Version)
	}
}

func TestDeclarations(t *testing.T) {
	raw := []byte("HTTP/1.1 200 OK\r\nServer: Apache/2.4.38 (Debian) OpenSSL/1.0.2q PHP/5.6.40\r\nX-Jenkins: 2.401.3\r\n" +
		"X-Gitea-Version: 1.21.4\r\nX-Tomcat: Apache Tomcat/9.0.1\r\n\r\n<meta name=\"generator\" content=\"WordPress 7.0.3\">")
	decls := declarations(raw)
	for product, want := range map[string]string{"Apache": "2.4.38", "openssl": "1.0.2q", "PHP": "5.6.40", "jenkins": "2.401.3",
		"Gitea": "1.21.4", "Apache Tomcat": "9.0.1", "WordPress": "7.0.3", "nginx": ""} {
		if got := declaredVersion(decls, product); got != want {
			t.Errorf("%s: got %q want %q", product, got, want)
		}
	}
	if !claimedByOther(decls, "5.6.40", NormalizeName("ThinkPHP")) || claimedByOther(decls, "5.6.40", NormalizeName("php")) {
		t.Error("claims")
	}
}

func TestVersionNeedsConfidence(t *testing.T) {
	m := newMock()
	m.versionP = 0.6
	accepted, err := newJudge(m).Refine(context.Background(), []byte(bodyRaw), testFrames())
	if err != nil {
		t.Fatal(err)
	}
	if v := accepted["jenkins"].Version; v != "" {
		t.Fatalf("low-confidence version written: %q", v)
	}
}

func TestFailedRoundLeavesFrames(t *testing.T) {
	m := newMock()
	m.fail = true
	frames := testFrames()
	before, _ := json.Marshal(frames)
	accepted, err := newJudge(m).Refine(context.Background(), []byte(jenkinsRaw), frames)
	if err == nil || accepted != nil {
		t.Fatal("expected error")
	}
	if after, _ := json.Marshal(frames); string(after) != string(before) {
		t.Fatalf("frames changed on failure:\n%s\n%s", before, after)
	}
}

func TestCache(t *testing.T) {
	m := newMock()
	j := newJudge(m)
	for i := 0; i < 2; i++ {
		accepted, err := j.Refine(context.Background(), []byte(bodyRaw), testFrames())
		if err != nil {
			t.Fatal(err)
		}
		if accepted["jenkins"].Version != "2.401.3" {
			t.Fatalf("run %d: cached answers not applied", i)
		}
	}
	if m.calls != 2 || j.CacheHits != 2 {
		t.Fatalf("calls=%d hits=%d", m.calls, j.CacheHits)
	}
}

func TestClassifyAlone(t *testing.T) {
	m := newMock()
	j := New(m)
	p, _ := NewPage([]byte(jenkinsRaw))
	r := newRound(p)
	var kind Kind
	var generic bool
	classifyRound(r, &kind, &generic)
	var custom float64
	r.add("honeypot", Binary("Is this a honeypot?"), func(a Answer) { custom = a.Yes })
	if err := r.ask(context.Background(), j); err != nil {
		t.Fatal(err)
	}
	if strings.Join(m.requests[0], ",") != "generic,honeypot,page_kind" || kind != KindLogin || !generic || custom != 0.7 {
		t.Fatalf("requests=%v kind=%q custom=%v", m.requests, kind, custom)
	}
	if err := newRound(p).ask(context.Background(), j); err != nil || m.calls != 1 {
		t.Fatalf("empty round sent a request: %v %d", err, m.calls)
	}
	r = newRound(p)
	r.add("x", Binary("?"), nil)
	r.add("x", Binary("?"), nil)
	if err := r.ask(context.Background(), j); err == nil {
		t.Fatal("duplicate key accepted")
	}
}

func TestMemoryCacheEvicts(t *testing.T) {
	c := NewMemoryCache(2)
	c.Put("a", 0, []byte("1"))
	c.Put("b", 0, []byte("2"))
	c.Get("a", 0, 0)
	c.Put("c", 0, []byte("3"))
	if _, ok := c.Get("b", 0, 0); ok {
		t.Fatal("least recently used entry kept")
	}
	if v, ok := c.Get("a", 0, 0); !ok || string(v) != "1" {
		t.Fatal("recent entry evicted")
	}
	if _, ok := c.Get("a", 0xff, 1); ok {
		t.Fatal("signature 8 bits away matched")
	}
	if v, ok := c.Get("a", 0x1, 1); !ok || string(v) != "1" {
		t.Fatal("signature 1 bit away missed")
	}
	if _, ok := c.Get("a", 0x1, 0); ok {
		t.Fatal("signature 1 bit away matched at distance 0")
	}
	if _, ok := c.Get("a", 0x3, 1); ok {
		t.Fatal("signature 2 bits away matched")
	}
}

// The same product page on another host (other token, date, host name) reuses
// the answers; a different page does not.
func TestSimilarPagesShareAnswers(t *testing.T) {
	// Same page on another host: other session, build number and date.
	page := func(build, date string) string {
		return strings.Replace(jenkinsRaw, "We moved here from WordPress.", "We moved here from WordPress. Build "+build+", "+date+".", 1)
	}
	orig, variant := page("101", "2026-09-24"), page("2087", "2025-01-03")
	a, _ := NewPage([]byte(orig))
	b, _ := NewPage([]byte(variant))
	other, _ := NewPage([]byte("HTTP/1.1 200 OK\r\nServer: Apache\r\n\r\n<title>Index of /</title><a href=\"a.txt\">a.txt</a>"))
	near := func(x, y *Page) bool { return bits.OnesCount64(x.signature()^y.signature()) <= DefaultSimilarDistance }
	if !near(a, b) || near(a, other) {
		t.Fatalf("signatures: %x %x %x", a.signature(), b.signature(), other.signature())
	}
	for _, distance := range []int{DefaultSimilarDistance, 0} {
		m := newMock()
		j := New(m)
		j.SimilarDistance = distance
		for _, raw := range []string{orig, variant} {
			if kind, _, err := j.Classify(context.Background(), []byte(raw)); err != nil || kind != KindLogin {
				t.Fatalf("kind %q err %v", kind, err)
			}
		}
		if want := map[int]int64{DefaultSimilarDistance: 1, 0: 2}[distance]; m.calls != want {
			t.Fatalf("distance %d: calls=%d, want %d", distance, m.calls, want)
		}
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
	if strings.Join(got, ",") != "3.4,8.1SP2,3.7.1" {
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

// A server's own page has no primary application; its version is still resolved.
func TestVersionWithoutPrimary(t *testing.T) {
	m := newMock()
	m.primary = noneOfThem
	frames := common.Frameworks{}
	frames.Add(common.NewFramework("nginx", common.FrameFromFingers))
	accepted, err := New(m).Refine(context.Background(), []byte(bodyRaw), frames)
	if err != nil {
		t.Fatal(err)
	}
	if accepted.Primary() != nil || accepted["nginx"].Version != "1.24.0" {
		t.Fatalf("server version not resolved: %+v", accepted["nginx"])
	}
}

// Refine of its own result sends nothing: judged hits are skipped and the
// remaining questions are answered by the cache.
func TestRefineIsIdempotent(t *testing.T) {
	m := newMock()
	j := newJudge(m)
	first, err := j.Refine(context.Background(), []byte(bodyRaw), testFrames())
	if err != nil {
		t.Fatal(err)
	}
	second, err := j.Refine(context.Background(), []byte(bodyRaw), first)
	if err != nil {
		t.Fatal(err)
	}
	if m.calls != 2 || len(second) != len(first) || second["jenkins"].Version != "2.401.3" {
		t.Fatalf("calls=%d first=%v second=%v requests=%v", m.calls, first, second, m.requests)
	}
}

// Many workers judging the same page at once (a scan hitting one product
// everywhere) cost one request.
func TestConcurrentSimilarPagesMerge(t *testing.T) {
	m := newMock()
	m.delay = 100 * time.Millisecond
	c := New(m)
	var wg sync.WaitGroup
	kinds := make([]Kind, 20)
	for i := range kinds {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			raw := strings.Replace(jenkinsRaw, "JSESSIONID.1=x", fmt.Sprintf("JSESSIONID.1=%d", i), 1)
			kind, _, err := c.Classify(context.Background(), []byte(raw))
			if err != nil {
				t.Error(err)
			}
			kinds[i] = kind
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
	c := New(m)
	if _, _, err := c.Classify(context.Background(), []byte(jenkinsRaw)); err != nil {
		t.Fatal(err)
	}
	p, _ := NewPage([]byte(jenkinsRaw))
	r := newRound(p)
	var kind Kind
	var generic bool
	classifyRound(r, &kind, &generic)
	r.add("extra", Binary("Is this page served over a CDN?"), nil)
	if err := r.ask(context.Background(), c); err != nil || kind != KindLogin {
		t.Fatalf("err %v kind %q", err, kind)
	}
	if len(m.requests) != 2 || strings.Join(m.requests[1], ",") != "extra" {
		t.Fatalf("requests: %v", m.requests)
	}
}

// Versions are resolved for the primary application first, then other
// applications, servers and libraries; unjudged hits last.
func TestByImportance(t *testing.T) {
	frames := common.Frameworks{}
	for name, j := range map[string]*common.Judgement{"jquery": {Layer: LayerFrontend}, "apache": {Layer: LayerServer},
		"ubuntu": {Layer: LayerDevice}, "gitlab": {Layer: LayerApplication, Primary: true}, "unjudged": nil} {
		f := common.NewFramework(name, common.FrameFromFingers)
		f.Judge = j
		frames.Add(f)
	}
	var got []string
	for _, f := range byImportance(frames) {
		got = append(got, f.Name)
	}
	if strings.Join(got, ",") != "gitlab,ubuntu,apache,jquery,unjudged" {
		t.Fatalf("order: %v", got)
	}
}

// Sparse pages with common headers must not look alike: CJK text counts, and
// similar pages must share a title.
func TestUnrelatedSparsePagesDoNotShare(t *testing.T) {
	head := "HTTP/1.1 200 OK\r\nServer: nginx\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<script src=\"/js/jquery.min.js\"></script>"
	a, _ := NewPage([]byte(head + "<title>职业规划咨询</title><p>生涯规划师与高考志愿规划，帮助学生找到方向</p>"))
	b, _ := NewPage([]byte(head + "<title>官方网站</title><p>在线娱乐平台，注册即送体验金</p>"))
	if bits.OnesCount64(a.signature()^b.signature()) <= DefaultSimilarDistance && a.similarityScope() == b.similarityScope() {
		t.Fatalf("unrelated pages share answers: %x %x", a.signature(), b.signature())
	}
}
