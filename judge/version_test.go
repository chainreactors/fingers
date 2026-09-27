package judge

import (
	"fmt"
	"strings"
	"testing"

	"github.com/chainreactors/fingers/judge/internal/evidence"
)

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

func TestVersionCandidatesFromRealResponseEvidence(t *testing.T) {
	raw := []byte("HTTP/1.1 200 OK\r\nServer: Apache/2.4.38 OpenSSL/1.0.2q PHP/5.6.40\r\nX-New-Api-Version: v1.0.0-rc.35\r\n\r\n<script src=\"/Scripts/JQuery/jquery-3.6.3.min.js\"></script>")
	got := map[string]bool{}
	for _, c := range extractVersions(raw, 40) {
		got[c.Value] = true
	}
	for _, want := range []string{"2.4.38", "1.0.2q", "5.6.40", "1.0.0-rc.35", "3.6.3"} {
		if !got[want] {
			t.Errorf("missing %s in %v", want, got)
		}
	}
	if got["1.0.2"] {
		t.Fatal("truncated OpenSSL version")
	}
}

func TestVersionCandidatesDoNotDiscardLateProductEvidence(t *testing.T) {
	var b strings.Builder
	b.WriteString("HTTP/1.1 200 OK\r\n\r\n<svg>")
	for i := 0; i < 80; i++ {
		b.WriteString(" " + string(rune('a'+i%26)) + " ")
		b.WriteString(strings.Repeat("1", i/10+1) + ".25 ")
	}
	// Add distinct numbers to exceed the shortlist.
	for _, n := range []string{"10.11", "11.12", "12.13", "13.14", "14.15", "15.16", "16.17", "17.18", "18.19", "19.20"} {
		b.WriteString(n + " ")
	}
	b.WriteString("</svg><script src=\"/jquery/jquery.min.js?ver=3.7.1\"></script>")
	found := false
	for _, c := range extractVersions([]byte(b.String()), 5) {
		found = found || c.Value == "3.7.1"
	}
	if !found {
		t.Fatal("early numeric noise evicted late library version")
	}
}

func TestCalendarVersionAndGeneratorName(t *testing.T) {
	raw := []byte("HTTP/1.1 200 OK\r\n\r\n<title>Custom Search</title><meta name=\"generator\" content=\"searxng/2026.9.23+3cd69d30e\">")
	p, err := evidence.NewPage(raw)
	if err != nil {
		t.Fatal(err)
	}
	foundName, foundVersion := false, false
	for _, name := range evidence.Names(p.Generator, p.Title, p.Text, p.Headers, p.Scripts) {
		foundName = foundName || NormalizeName(name) == "searxng"
	}
	for _, v := range extractVersions(raw, 40) {
		foundVersion = foundVersion || v.Value == "2026.9.23+3cd69d30e"
	}
	if !foundName || !foundVersion {
		t.Fatalf("name=%t version=%t", foundName, foundVersion)
	}
}

// Protocol and markup format versions are facts code excludes: the provider
// is never offered them as a product's version.
func TestFormatVersionsAreNotCandidates(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\nServer: GitHub.com\r\nVia: 1.1 varnish, HTTP/1.0 proxy\r\n\r\n" +
		`<?xml version="1.0"?><svg id="caddy" viewBox="0 0 379 114" version="1.1"></svg>` +
		`<script src="/app.js?v=2.4.1"></script><p>Varnish 7.4.2</p>`
	var got []string
	for _, c := range extractVersions([]byte(raw), 10) {
		got = append(got, c.Value)
	}
	if strings.Join(got, ",") != "2.4.1,7.4.2" {
		t.Fatalf("got %v", got)
	}
}
