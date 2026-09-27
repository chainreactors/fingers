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
	"github.com/chainreactors/fingers/judge/internal/evidence"
	"github.com/chainreactors/utils/jev"
)

const jenkinsRaw = "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nX-Jenkins: 2.401.3\r\nSet-Cookie: JSESSIONID.1=x; Path=/\r\nContent-Type: text/html\r\n\r\n" +
	`<html><head><title>Sign in [Jenkins]</title><script src="/static/prototype.js"></script></head>` +
	`<body><script>var x=1;</script><p>We moved here from WordPress.</p>` +
	`<input name="j_username" type="text"><input name="j_password" type="password"></body></html>`

func TestNewPage(t *testing.T) {
	s, err := evidence.NewPage([]byte(jenkinsRaw))
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
	if !declares(s, "jenkins") || !declares(s, "nginx") || declares(s, "wordpress") || declares(s, "jenk") {
		t.Fatal("declares")
	}
}

// mock is a Provider ruling from a table keyed by claim kind and the
// product named in backticks; it records the claim keys of each call.
type mock struct {
	mu         sync.Mutex
	delay      time.Duration
	calls      int64
	requests   [][]string
	fail       bool
	confidence float64
	presence   map[string]string // product -> presence option
	versions   map[string]string // product -> version picked, if among the options
	coverage   string
	lastState  map[string]interface{}
}

func newMock() *mock {
	return &mock{
		confidence: 0.95,
		presence:   map[string]string{"wordpress": OptionMentioned, "apache tomcat": OptionRunning, "prototype": OptionRunning},
		versions:   map[string]string{"jenkins": "2.401.3", "nginx": "1.24.0"},
	}
}

// named is the first product named in backticks, skipping state field names.
func named(q jev.Claim) string {
	parts := strings.Split(q.Statement, "`")
	for i := 1; i < len(parts); i += 2 {
		if parts[i] != "version_strings" && !strings.HasPrefix(parts[i], "matches.") {
			return parts[i]
		}
	}
	return ""
}

func (m *mock) ID() string { return "mock" }

func (m *mock) Judge(ctx context.Context, state interface{}, claims map[string]jev.Claim) (map[string]jev.Ruling, error) {
	atomic.AddInt64(&m.calls, 1)
	time.Sleep(m.delay)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return nil, errors.New("provider down")
	}
	data, _ := json.Marshal(state)
	_ = json.Unmarshal(data, &m.lastState)
	rulings := map[string]jev.Ruling{}
	var keys []string
	for k, q := range claims {
		keys = append(keys, k)
		name := strings.ToLower(named(q))
		switch {
		case strings.HasPrefix(k, "presence_"):
			v := m.presence[name]
			if v == "" {
				v = jev.OptionInsufficient
			}
			rulings[k] = jev.Ruling{Option: v, Confidence: m.confidence}
		case strings.HasPrefix(k, "version_"):
			option := notStated
			if v, ok := m.versions[name]; ok {
				if _, offered := q.Options[v]; offered {
					option = v
				}
			}
			rulings[k] = jev.Ruling{Option: option, Confidence: m.confidence}
		case k == "coverage":
			rulings[k] = jev.Ruling{Option: m.coverage, Confidence: m.confidence}
		default:
			rulings[k] = jev.Ruling{Option: jev.OptionInsufficient, Confidence: m.confidence}
		}
	}
	sort.Strings(keys)
	m.requests = append(m.requests, keys)
	return rulings, nil
}

func testFrames() common.Frameworks {
	fs := common.Frameworks{}
	fs.Add(common.NewFramework("nginx", common.FrameFromFingers))
	fs.Add(common.NewFramework("wordpress", common.FrameFromGoby))
	fs.Add(common.NewFramework("jenkins", common.FrameFromFingerprintHub))
	fs.Add(common.NewFramework("apache-tomcat", common.FrameFromFingers))
	fs.Add(common.NewFramework("apache tomcat", common.FrameFromWappalyzer))
	fs.Add(common.NewFramework("hsts", common.FrameFromWappalyzer))
	return fs
}

// bodyRaw states versions only in the body, so the provider has to pick them.
const bodyRaw = "HTTP/1.1 200 OK\r\nServer: nginx\r\nSet-Cookie: JSESSIONID.1=x; Path=/\r\n\r\n" +
	`<html><head><title>Sign in [Jenkins]</title><script src="/static/prototype.js"></script></head>` +
	`<body><p>We moved here from WordPress.</p><footer>Jenkins 2.401.3, nginx 1.24.0</footer></body></html>`

func TestInspect(t *testing.T) {
	m := newMock()
	j := New(jev.Cached(m, jev.DefaultCacheSize))
	all, err := j.Inspect(context.Background(), []byte(jenkinsRaw), testFrames())
	if err != nil {
		t.Fatal(err)
	}
	if w := all["wordpress"].Judge; w == nil || !w.Rejected || w.Option != OptionMentioned || w.Outcome != "refuted" || len(w.Evidence) == 0 || !strings.Contains(w.Evidence[0], "WordPress") {
		t.Errorf("text-only wordpress not rejected on its evidence: %+v", w)
	}
	for _, name := range []string{"nginx", "jenkins"} {
		if v := all[name].Judge; v.Rejected || v.Option != OptionDeclared || v.Outcome != "holds" {
			t.Errorf("%s named in a header must be declared: %+v", name, v)
		}
	}
	if h := all["hsts"].Judge; !h.Rejected || h.Option != OptionAbsent || h.Outcome != "refuted" {
		t.Errorf("hsts without the header must be absent: %+v", h)
	}
	if all["apache tomcat"].Judge.Duplicate == all["apache-tomcat"].Judge.Duplicate {
		t.Errorf("exactly one tomcat spelling must be a dup")
	}
	// Facts are not asked: only wordpress and tomcat are claims.
	if len(m.requests) != 1 || strings.Join(m.requests[0], ",") != "presence_apachetomcat,presence_wordpress" {
		t.Fatalf("requests: %v", m.requests)
	}
	claims, _ := json.Marshal(m.lastState["matches"])
	if !strings.Contains(string(claims), "We moved here from WordPress") {
		t.Errorf("claim evidence missing from the state: %s", claims)
	}

	accepted, err := j.Inspect(context.Background(), []byte(jenkinsRaw), testFrames())
	accepted = accepted.Accepted()
	if err != nil {
		t.Fatal(err)
	}
	if len(accepted) != 3 { // nginx, jenkins, tomcat
		t.Errorf("accepted: %v", accepted)
	}
	// Both versions are bound by name in the headers: taken without asking.
	if accepted["jenkins"].Version != "2.401.3" || accepted["nginx"].Version != "1.24.0" {
		t.Errorf("versions: jenkins %q nginx %q", accepted["jenkins"].Version, accepted["nginx"].Version)
	}
	// The presence come from the cache; tomcat is offered no version, since
	// both strings are bound by name to other products.
	if len(m.requests) != 1 {
		t.Errorf("cached presence were asked again: %v", m.requests)
	}
}

// DropInsufficient decides what an undecided claim does; a ruling below
// MinConfidence is undecided whatever it chose.
func TestInsufficient(t *testing.T) {
	for _, c := range []struct {
		on         bool
		confidence float64
		option     string
		rejected   bool
	}{
		{false, 0.95, OptionRunning, false},
		{false, 0.2, jev.OptionInsufficient, false},
		{true, 0.2, jev.OptionInsufficient, true},
		{true, 0.95, OptionRunning, false},
	} {
		m := newMock()
		m.confidence = c.confidence
		j := New(jev.Cached(m, jev.DefaultCacheSize))
		j.DropInsufficient = c.on
		all, err := j.Inspect(context.Background(), []byte(jenkinsRaw), testFrames())
		if err != nil {
			t.Fatal(err)
		}
		tomcat := all["apache tomcat"].Judge
		if all["apache-tomcat"].Judge.Duplicate {
			tomcat = all["apache-tomcat"].Judge
		}
		outcome := "holds"
		if c.option == jev.OptionInsufficient {
			outcome = "insufficient"
		}
		if tomcat.Option != OptionRunning || tomcat.Outcome != outcome || tomcat.Rejected != c.rejected {
			t.Errorf("%+v: tomcat %+v", c, tomcat)
		}
	}
}

// A rule that matched text unrelated to its product is a false positive,
// removed like a mere mention, and the matched text reaches the provider.
func TestUnrelatedIsRejected(t *testing.T) {
	m := newMock()
	m.presence["apache tomcat"] = OptionUnrelated
	frames := testFrames()
	for _, f := range frames {
		if f.Name == "apache tomcat" || f.Name == "apache-tomcat" {
			f.MatchDetail = &common.MatchDetail{MatcherType: "word", MatcherValue: "jenkins"}
		}
	}
	all, err := New(m).Inspect(context.Background(), []byte(jenkinsRaw), frames)
	if err != nil {
		t.Fatal(err)
	}
	tomcat := all["apache tomcat"].Judge
	if all["apache-tomcat"].Judge.Duplicate {
		tomcat = all["apache-tomcat"].Judge
	}
	if tomcat.Option != OptionUnrelated || !tomcat.Rejected || len(tomcat.Evidence) == 0 || !strings.Contains(tomcat.Evidence[0], `matched "Jenkins"`) {
		t.Fatalf("tomcat %+v", tomcat)
	}
}

// Versions stated only in the body are picked by the provider, all kept
// products in one request, each from its own candidates.
func TestInspectVersionsEveryProduct(t *testing.T) {
	m := newMock()
	m.presence["jenkins"] = OptionRunning
	accepted, err := New(m).Inspect(context.Background(), []byte(bodyRaw), testFrames())
	accepted = accepted.Accepted()
	if err != nil {
		t.Fatal(err)
	}
	if accepted["jenkins"].Version != "2.401.3" || accepted["nginx"].Version != "1.24.0" {
		t.Fatalf("versions: jenkins %q nginx %q", accepted["jenkins"].Version, accepted["nginx"].Version)
	}
	if len(m.requests) != 2 || !strings.HasPrefix(strings.Join(m.requests[1], ","), "version_apachetomcat,version_jenkins") {
		t.Fatalf("requests: %v", m.requests)
	}
	if _, ok := m.lastState["version_strings"]; !ok {
		t.Errorf("version strings not in the state: %v", m.lastState)
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
	m.presence["jenkins"] = OptionRunning
	m.confidence = 0.2
	accepted, err := New(m).Inspect(context.Background(), []byte(bodyRaw), testFrames())
	accepted = accepted.Accepted()
	if err != nil {
		t.Fatal(err)
	}
	if v := accepted["jenkins"].Version; v != "" {
		t.Fatalf("low-confidence version written: %q", v)
	}
}

// A failed provider leaves the input untouched, and the result still holds
// what code established: duplicates merged, header facts decided, the
// undecided hits kept unjudged.
func TestFailedProviderKeepsFacts(t *testing.T) {
	m := newMock()
	m.fail = true
	frames := testFrames()
	before, _ := json.Marshal(frames)
	accepted, err := New(m).Inspect(context.Background(), []byte(jenkinsRaw), frames)
	accepted = accepted.Accepted()
	if err == nil {
		t.Fatal("expected error")
	}
	if after, _ := json.Marshal(frames); string(after) != string(before) {
		t.Fatalf("frames changed on failure:\n%s\n%s", before, after)
	}
	// nginx, jenkins (declared), wordpress and one tomcat (unjudged); hsts absent, one tomcat a duplicate.
	if len(accepted) != 4 || accepted["hsts"] != nil || accepted["wordpress"] == nil || accepted["wordpress"].Judge != nil ||
		accepted["jenkins"].Judge.Option != OptionDeclared {
		t.Fatalf("accepted on failure: %v", accepted)
	}
}

func TestCache(t *testing.T) {
	m := newMock()
	m.presence["jenkins"] = OptionRunning
	j := New(jev.Cached(m, jev.DefaultCacheSize))
	for i := 0; i < 2; i++ {
		accepted, err := j.Inspect(context.Background(), []byte(bodyRaw), testFrames())
		accepted = accepted.Accepted()
		if err != nil {
			t.Fatal(err)
		}
		if accepted["jenkins"].Version != "2.401.3" {
			t.Fatalf("run %d: cached rulings not applied", i)
		}
	}
	if m.calls != 2 {
		t.Fatalf("calls=%d", m.calls)
	}
}

func TestExtractVersionsPrefixes(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\n\r\n<meta content=\"Discuz! X3.4\"><title>V8.1SP2</title> 10.0.0.5 jquery.min.js?ver=3.7.1<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">{\"success_fraction\":0.0}"
	var got []string
	for _, c := range extractVersions([]byte(raw), 10) {
		got = append(got, c.Value)
	}
	if strings.Join(got, ",") != "3.4,8.1SP2,3.7.1" {
		t.Fatalf("got %v", got)
	}
}

func TestWordBoundary(t *testing.T) {
	if containsWord("take action now", "acti") || containsWord("x-github-request-id: 1", "git") {
		t.Fatal("substring matched")
	}
	if !containsWord("sign in [jenkins]", "jenkins") || !containsWord("泛微oa", "泛微") {
		t.Fatal("word missed")
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

// Versions are ordered by their resolved outcome.
func TestVersionOrder(t *testing.T) {
	frames := common.Frameworks{}
	for name, j := range map[string]*common.Judgement{"jquery": {Option: jev.OptionInsufficient}, "apache": {Option: OptionDeclared, Outcome: jev.Holds.String()},
		"gitlab": {Option: OptionRunning, Outcome: jev.Holds.String()}, "unjudged": nil} {
		f := common.NewFramework(name, common.FrameFromFingers)
		f.Judge = j
		frames.Add(f)
	}
	var got []string
	for _, f := range versionOrder(frames) {
		got = append(got, f.Name)
	}
	if strings.Join(got, ",") != "apache,gitlab,jquery,unjudged" {
		t.Fatalf("order: %v", got)
	}
}

// Rule excerpts include matches deep in the response.
func TestEvidenceQuotesTheMatcher(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n<title>没有找到站点</title><body>" + strings.Repeat("<p>filler</p>", 300) +
		"<p class=\"t1\">您的请求在Web服务器中没有找到对应的站点！</p></body>"
	p, _ := evidence.NewPage([]byte(raw))
	f := common.NewFramework("宝塔", common.FrameFromFingers)
	f.MatchDetail = &common.MatchDetail{MatcherType: "regexp", MatcherValue: "没有找到对应的站点"}
	frames := common.Frameworks{}
	frames.Add(f)
	groups := groupProducts(frames)
	excerpts := evidenceFor(p.Raw, groups[0])
	if len(groups) != 1 || len(excerpts) == 0 ||
		!strings.Contains(excerpts[0].Text, "您的请求在Web服务器中没有找到对应的站点") || excerpts[0].Where != "body" {
		t.Fatalf("evidence: %+v", groups[0])
	}
	if strings.Contains(p.Text, "您的请求") {
		t.Fatal("test page too short: the compact view already carries the match")
	}
}
