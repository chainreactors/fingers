package gen

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	fingerlib "github.com/chainreactors/fingers/fingers"
	"github.com/chainreactors/fingers/judge"
)

// names answers yes for the product named in backticks, no otherwise.
type names string

func (names) ID() string { return "names" }

func (n names) Judge(_ context.Context, _ interface{}, qs map[string]judge.Question) (map[string]judge.Answer, error) {
	out := map[string]judge.Answer{}
	for key, q := range qs {
		if strings.Contains(q.Instructions, "`"+string(n)+"`") {
			out[key] = judge.Answer{Yes: 0.95}
		} else {
			out[key] = judge.Answer{Yes: 0.05}
		}
	}
	return out, nil
}

func TestGeneratorPassiveVersionAndValidation(t *testing.T) {
	positive1 := []byte("HTTP/1.1 200 OK\r\nServer: nginx/2.401.3\r\nX-Jenkins: 2.401.3\r\n\r\n<title>Jenkins</title>")
	positive2 := []byte("HTTP/1.1 200 OK\r\nServer: nginx/2.402.1\r\nX-Jenkins: 2.402.1\r\n\r\n<title>Jenkins</title>")
	negative := []byte("HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n<title>Blog</title><p>X-Jenkins: 9.9.9 release notes</p>")
	g := New(nil).Name("Jenkins").PositiveVersion(positive1, "2.401.3").PositiveVersion(positive2, "2.402.1").Negative(negative)
	f, err := g.Generate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if f.Name != "Jenkins" || len(f.Rules) < 2 {
		t.Fatalf("fingerprint: %+v", f)
	}
	for _, sample := range []struct {
		raw     []byte
		version string
	}{{positive1, "2.401.3"}, {positive2, "2.402.1"}} {
		frame, _, ok := f.PassiveMatch(fingerlib.NewContent(sample.raw, "", true))
		if !ok || frame.Version != sample.version {
			t.Fatalf("version matcher = %+v, %v", frame, ok)
		}
	}
	compiled := len(f.Rules[0].Regexps.CompliedRegexp)
	if err := g.Validate(f); err != nil || len(f.Rules[0].Regexps.CompliedRegexp) != compiled {
		t.Fatalf("Validate mutated compiled matcher: %v", err)
	}
	if err := g.Validate(&fingerlib.Finger{Name: "Jenkins", Rules: fingerlib.Rules{&fingerlib.Rule{Regexps: &fingerlib.Regexps{Body: []string{"jenkins"}}}}}); err == nil {
		t.Fatal("validator accepted rule matching negative sample")
	}
}

func TestGeneratorActiveAndProbeWith(t *testing.T) {
	base := []byte("HTTP/1.1 200 OK\r\n\r\n<title>Login</title>")
	request := []byte("/admin")
	positive := []byte("HTTP/1.1 200 OK\r\nX-Orion: console\r\n\r\nOrion console")
	negative := []byte("HTTP/1.1 404 Not Found\r\n\r\nmissing")
	g := New(nil).Name("Orion").Positive(base)
	if err := g.ProbeWith(context.Background(), request, func(_ context.Context, got []byte) ([]byte, error) {
		if !bytes.Equal(got, request) {
			return nil, errors.New("wrong request")
		}
		return positive, nil
	}); err != nil {
		t.Fatal(err)
	}
	g.Negative(base).Probe(request, negative)
	f, err := g.Generate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Rules) != 1 || f.Rules[0].SendDataStr != string(request) || !f.IsActive {
		t.Fatalf("active rule: %+v", f)
	}
	if err := g.Validate(f); err != nil {
		t.Fatal(err)
	}
	if len(f.Rules[0].Regexps.CompliedRegexp) != 0 {
		t.Fatal("Validate changed compiled rules")
	}
	if _, err := New(nil).Name("Orion").Positive(base).Probe(request, positive).Negative(base).Generate(context.Background()); err == nil {
		t.Fatal("generated active rule without a negative probe")
	}
}

func TestGeneratorSelectsNameByDefault(t *testing.T) {
	positive := []byte("HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n<title>Orion</title><p>Orion console</p>")
	negative := []byte("HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n<title>Other</title>")
	j := judge.New(names("Orion"))
	f, err := New(j).Positive(positive).Negative(negative).Generate(context.Background())
	if err != nil || f.Name != "Orion" {
		t.Fatalf("auto name = %+v, %v", f, err)
	}
}

func TestGeneratorActiveVersion(t *testing.T) {
	base := []byte("HTTP/1.1 200 OK\r\n\r\n<title>Login</title>")
	request := []byte("/version")
	positive := []byte("HTTP/1.1 200 OK\r\nX-Orion: 3.1.2\r\n\r\nversion")
	negative := []byte("HTTP/1.1 200 OK\r\n\r\nnot installed")
	g := New(nil).Name("Orion").PositiveVersion(base, "3.1.2").Probe(request, positive).Negative(base).Probe(request, negative)
	f, err := g.Generate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	frame, _, ok := f.ActiveMatch(2, func(got []byte) ([]byte, bool) { return positive, bytes.Equal(got, request) })
	if !ok || frame.Version != "3.1.2" {
		t.Fatalf("active version = %+v, %v", frame, ok)
	}
}

func TestGeneratorCoversDifferentPositiveVariants(t *testing.T) {
	base := "HTTP/1.1 200 OK\r\n%s\r\n<title>Welcome</title>"
	first := []byte(fmt.Sprintf(base, "X-Orion-Instance: ready\r\n"))
	second := []byte(fmt.Sprintf(base, "X-Orion-Service: yes\r\n"))
	other := []byte(fmt.Sprintf(base, "Server: nginx\r\n"))
	g := New(nil).Name("Orion").Positive(first).Positive(second).Negative(other)
	f, err := g.Generate(context.Background())
	if err != nil || len(f.Rules) != 2 {
		t.Fatalf("variant rules = %+v, %v", f, err)
	}
}

func TestGeneratedVersionHandlesHyphenatedHeaderAndReleaseSuffix(t *testing.T) {
	raw := func(v string) []byte {
		return []byte("HTTP/1.1 200 OK\r\nServer: nginx\r\nX-New-Api-Version: v" + v + "\r\n\r\n<title>New API</title>")
	}
	neg := []byte("HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n<title>Welcome</title>")
	g := New(nil).Name("New API").PositiveVersion(raw("1.0.0-rc.35"), "1.0.0-rc.35").Negative(neg)
	f, err := g.Generate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"1.0.0-rc.35", "1.2.0-rc.2", "2.0.1"} {
		frame, _, matched := f.PassiveMatch(fingerlib.NewContent(raw(version), "", true))
		if !matched || frame.Version != version {
			t.Fatalf("version=%s matched=%t frame=%+v", version, matched, frame)
		}
	}
}

func TestGeneratedMetaRuleSurvivesTitleAndCalendarVersionChanges(t *testing.T) {
	page := func(title, version string) []byte {
		return []byte("HTTP/1.1 200 OK\r\n\r\n<title>" + title + "</title><meta name=\"generator\" content=\"searxng/" + version + "\">")
	}
	negative := []byte("HTTP/1.1 200 OK\r\n\r\n<title>SearXNG Documentation</title><p>Install SearXNG</p>")
	f, err := New(nil).Name("SearXNG").PositiveVersion(page("Search One", "2026.9.23+3cd69d30e"), "2026.9.23+3cd69d30e").Negative(negative).Generate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got, _, matched := f.PassiveMatch(fingerlib.NewContent(page("Different Search", "2026.9.25+d8ae3abd5"), "", true))
	if !matched || got.Version != "2026.9.25+d8ae3abd5" {
		t.Fatalf("matched=%t got=%+v", matched, got)
	}
	if _, _, matched := f.PassiveMatch(fingerlib.NewContent(negative, "", true)); matched {
		t.Fatal("documentation matched")
	}
}

func TestGeneratedFooterVersionRequiresProductDeclaration(t *testing.T) {
	page := func(title, version string) []byte {
		return []byte("HTTP/1.1 200 OK\r\n\r\n<title>" + title + "</title><main>Log in</main><footer><div class=\"text-xs font-mono font-semibold\">\n v" + version + " @ mysql\n</div></footer>")
	}
	negative := page("Different Application", "2.18.0-be6aeb4")
	f, err := New(nil).Name("Wakapi").PositiveVersion(page("Wakapi – Coding Statistics", "2.18.0-be6aeb4"), "2.18.0-be6aeb4").Negative(negative).Generate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got, _, matched := f.PassiveMatch(fingerlib.NewContent(page("Wakapi – Coding Statistics", "2.12.0"), "", true))
	if !matched || got.Version != "2.12.0" {
		t.Fatalf("matched=%t got=%+v", matched, got)
	}
	if _, _, matched := f.PassiveMatch(fingerlib.NewContent(negative, "", true)); matched {
		t.Fatal("unguarded footer matched another product")
	}
}

func TestGeneratedApplicationDoesNotLearnSharedInfrastructure(t *testing.T) {
	for _, name := range []string{"IT Tools", "Docmost"} {
		positive := []byte("HTTP/1.1 200 OK\r\nServer: cloudflare\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<title>" + name + "</title>")
		negative := []byte("HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n<title>Different Application</title>")
		f, err := New(nil).Name(name).Positive(positive).Negative(negative).Generate(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		sameProxy := []byte("HTTP/1.1 200 OK\r\nServer: cloudflare\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n<title>Unrelated Application</title>")
		if _, _, matched := f.PassiveMatch(fingerlib.NewContent(sameProxy, "", true)); matched {
			t.Fatalf("%s learned shared infrastructure", name)
		}
		otherProxy := []byte("HTTP/1.1 200 OK\r\nServer: caddy\r\n\r\n<title>" + name + "</title>")
		if _, _, matched := f.PassiveMatch(fingerlib.NewContent(otherProxy, "", true)); !matched {
			t.Fatalf("%s requires original infrastructure", name)
		}
	}
}
