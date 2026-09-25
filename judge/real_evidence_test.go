package judge

import (
	"context"
	"strings"
	"testing"

	"github.com/chainreactors/fingers/common"
)

// Minimal public evidence retained from the 2026-09-25 corpus, not full pages.
func TestStaticApplicationDescriptionIsPreservedAsEvidence(t *testing.T) {
	description := "IT Tools is a free and open-source collection of handy online tools for developers."
	for _, meta := range []string{
		`<meta name="description" content="` + description + `">`,
		`<meta content="` + description + `" name="description">`,
	} {
		p, err := NewPage([]byte("HTTP/1.1 200 OK\r\n\r\n<title>IT Tools - Handy online tools for developers</title>" + meta))
		if err != nil || p.Description != description || !strings.Contains(p.haystack(), strings.ToLower(description)) {
			t.Fatalf("description evidence missing: %+v err=%v", p, err)
		}
		if strings.Contains(strings.Join(p.where("it tools"), ","), "header") {
			t.Fatal("description incorrectly treated as deterministic header evidence")
		}
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
func TestProtocolHitRequiresResponseEvidence(t *testing.T) {
	for _, tc := range []struct {
		name, header string
		yes          bool
		want         bool
	}{{"http基本认证", "", true, false}, {"hsts", "", true, false}, {"http基本认证", "WWW-Authenticate: Basic realm=\"test\"\r\n", false, true}, {"hsts", "Strict-Transport-Security: max-age=31536000\r\n", false, true}} {
		j := New(answerProvider(func(qs map[string]Question) map[string]Answer {
			out := map[string]Answer{}
			for k, q := range qs {
				if q.Type == TypeBinary {
					v := .01
					if tc.yes {
						v = .99
					}
					out[k] = Answer{Yes: v}
				} else if k == "page_kind" {
					out[k] = Answer{Choice: string(KindLogin)}
				} else if k == "primary" {
					out[k] = Answer{Choice: noneOfThem}
				} else {
					out[k] = Answer{Choice: string(LayerNotPresent)}
				}
			}
			return out
		}))
		hits := common.Frameworks{}
		hits.Add(common.NewFramework(tc.name, common.FrameFromGUESS))
		all, err := j.Inspect(context.Background(), []byte("HTTP/1.1 200 OK\r\n"+tc.header+"\r\n<script>Basic authentication documentation</script>"), hits)
		got := all.Accepted()
		if err != nil || (len(got) > 0) != tc.want {
			t.Errorf("%s evidence=%q got=%v err=%v", tc.name, tc.header, got, err)
		}
	}
}

func TestCalendarVersionAndGeneratorName(t *testing.T) {
	raw := []byte("HTTP/1.1 200 OK\r\n\r\n<title>Custom Search</title><meta name=\"generator\" content=\"searxng/2026.9.23+3cd69d30e\">")
	p, err := NewPage(raw)
	if err != nil {
		t.Fatal(err)
	}
	foundName, foundVersion := false, false
	for _, name := range pageNames(p) {
		foundName = foundName || NormalizeName(name) == "searxng"
	}
	for _, v := range extractVersions(raw, 40) {
		foundVersion = foundVersion || v.Value == "2026.9.23+3cd69d30e"
	}
	if !foundName || !foundVersion {
		t.Fatalf("name=%t version=%t", foundName, foundVersion)
	}
}
