package judge

import (
	"context"
	"strings"
	"testing"

	"github.com/chainreactors/fingers/common"
	"github.com/chainreactors/fingers/judge/internal/evidence"
	"github.com/chainreactors/utils/jev"
)

func TestPageDeclarations(t *testing.T) {
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

func TestWordBoundary(t *testing.T) {
	if indexWord("take action now", "acti") >= 0 || indexWord("x-github-request-id: 1", "git") >= 0 {
		t.Fatal("substring matched")
	}
	if indexWord("sign in [jenkins]", "jenkins") < 0 || indexWord("泛微oa", "泛微") < 0 {
		t.Fatal("word missed")
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

// Minimal public evidence retained from the 2026-09-25 corpus, not full pages.
func TestStaticApplicationDescriptionIsPreservedAsEvidence(t *testing.T) {
	description := "IT Tools is a free and open-source collection of handy online tools for developers."
	for _, meta := range []string{
		`<meta name="description" content="` + description + `">`,
		`<meta content="` + description + `" name="description">`,
	} {
		p, err := evidence.NewPage([]byte("HTTP/1.1 200 OK\r\n\r\n<title>IT Tools - Handy online tools for developers</title>" + meta))
		if err != nil || p.Description != description {
			t.Fatalf("description evidence missing: %+v err=%v", p, err)
		}
		if declares(p, "it tools") {
			t.Fatal("description incorrectly treated as deterministic header evidence")
		}
	}
}

// Protocol features are facts of the response head: decided by code, never
// asked, whatever a provider would rule.
func TestProtocolHitRequiresResponseEvidence(t *testing.T) {
	for _, tc := range []struct {
		name, header string
		want         bool
	}{{"http基本认证", "", false}, {"hsts", "", false}, {"http基本认证", "WWW-Authenticate: Basic realm=\"test\"\r\n", true}, {"hsts", "Strict-Transport-Security: max-age=31536000\r\n", true}} {
		asked := false
		j := New(rulingProvider(func(qs map[string]jev.Claim) map[string]jev.Ruling {
			asked = true
			return nil
		}))
		hits := common.Frameworks{}
		hits.Add(common.NewFramework(tc.name, common.FrameFromGUESS))
		all, err := j.Inspect(context.Background(), []byte("HTTP/1.1 200 OK\r\n"+tc.header+"\r\n<script>Basic authentication documentation</script>"), hits)
		got := all.Accepted()
		if err != nil || asked || (len(got) > 0) != tc.want {
			t.Errorf("%s evidence=%q got=%v asked=%v err=%v", tc.name, tc.header, got, asked, err)
		}
	}
}

func TestBasicChallengeUsesFullHeaderAndQuotedRealms(t *testing.T) {
	for _, tc := range []struct {
		header string
		want   bool
	}{
		{"WWW-Authenticate: Digest realm=\"" + strings.Repeat("x", 200) + "\", Basic realm=\"private\"\r\n", true},
		{"WWW-Authenticate: Digest realm=\"x, Basic fake\"\r\n", false},
		{"WWW-Authenticate: Digest realm=\"private\"\r\nWWW-Authenticate: Basic realm=\"private\"\r\n", true},
	} {
		p, err := evidence.NewPage([]byte("HTTP/1.1 401 Unauthorized\r\n" + tc.header + "\r\n"))
		if err != nil || protocolPresent(p, "http基本认证") != tc.want {
			t.Fatalf("header %q: %v", tc.header, err)
		}
	}
}

func TestIncidentalHeaderNamesAreNotDeclarations(t *testing.T) {
	raw := []byte("HTTP/1.1 302 Found\r\nLocation: https://docs.test/jenkins/2.401.3\r\nSet-Cookie: jenkins=x\r\nX-Github-Request-Id: jenkins\r\n\r\n")
	p, err := evidence.NewPage(raw)
	if err != nil {
		t.Fatal(err)
	}
	if declares(p, "jenkins") || declaredVersion(declarations(raw), "jenkins") != "" {
		t.Fatal("incidental URL/cookie text became a fact")
	}
}
