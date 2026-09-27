package fingers

import (
	"context"
	"strings"
	"testing"

	"github.com/chainreactors/fingers/judge"
	"github.com/chainreactors/utils/jev"
	"github.com/pkg/errors"
)

// With a Judge, the engine's own entry points return reviewed results:
// declared products are kept, a product the page only mentions is dropped,
// and a failing provider leaves the rule results in place.
func TestEngineJudge(t *testing.T) {
	engine, err := NewEngine(FingersEngine, WappalyzerEngine)
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte("HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/html\r\n\r\n" +
		`<title>Welcome to nginx!</title><p>Migrating from WordPress? <a href="/wp-login.php">wp-login.php</a> <script src="/wp-includes/js/jquery/jquery.min.js"></script></p>`)
	rules, _ := engine.DetectContent(raw)
	if rules["nginx"] == nil || len(rules) < 2 {
		t.Fatalf("rule results %v", rules)
	}
	engine.EnableMatchDetail()
	engine.Judge = judge.New(verdict(judge.OptionMentioned))
	reviewed, _ := engine.DetectContent(raw)
	if nginx := reviewed["nginx"]; nginx == nil || nginx.Judge == nil || nginx.Judge.Option != judge.OptionDeclared {
		t.Fatalf("declared nginx: %v", reviewed["nginx"])
	}
	for name, f := range reviewed {
		if f.Judge != nil && f.Judge.Rejected {
			t.Errorf("rejected %s returned", name)
		}
	}
	if len(reviewed) >= len(rules) {
		t.Fatalf("nothing dropped: %d reviewed of %d", len(reviewed), len(rules))
	}
	engine.Judge = judge.New(failing{})
	if fallback, _ := engine.DetectContent(raw); len(fallback) != len(rules) {
		t.Fatalf("failed provider changed results: %d of %d", len(fallback), len(rules))
	}
}

func TestEnableJudge(t *testing.T) {
	engine, err := NewEngine(FingersEngine)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(jev.EnvAPIKey, "")
	if err := engine.EnableJudge(""); err == nil || engine.Judge != nil {
		t.Fatal("enabled without a key")
	}
	if err := engine.EnableJudge("local-test"); err != nil || engine.Judge == nil || !engine.Fingers().MatchDetailEnabled {
		t.Fatalf("EnableJudge: %v", err)
	}
}

// verdict is a provider that rules every presence claim with one option and
// states no version.
type verdict string

func (verdict) ID() string { return "test" }

func (v verdict) Judge(ctx context.Context, state interface{}, claims map[string]jev.Claim) (map[string]jev.Ruling, error) {
	rulings := map[string]jev.Ruling{}
	for k := range claims {
		switch {
		case strings.HasPrefix(k, "presence_"):
			rulings[k] = jev.Ruling{Option: string(v), Confidence: 0.9}
		default:
			rulings[k] = jev.Ruling{Option: "not_stated", Confidence: 0.9}
		}
	}
	return rulings, nil
}

type failing struct{}

func (failing) ID() string { return "failing" }

func (failing) Judge(context.Context, interface{}, map[string]jev.Claim) (map[string]jev.Ruling, error) {
	return nil, errors.New("unavailable")
}

// Every engine that can record what a hit matched does so once enabled, and
// quotes text the response contains; disabled, results carry no detail.
func TestEnableMatchDetail(t *testing.T) {
	raw := []byte("HTTP/1.1 200 OK\r\nServer: nginx\r\nX-Powered-By: PHP/7.4.3\r\nContent-Type: text/html\r\n\r\n" +
		`<html><head><meta name="generator" content="WordPress 6.4"><title>Blog</title></head>` +
		`<body><link rel="stylesheet" href="/wp-content/themes/a/style.css"><script src="/wp-includes/js/jquery/jquery.min.js"></script></body></html>`)
	engines := []string{FingerPrintEngine, WappalyzerEngine, EHoleEngine, GobyEngine}
	for _, enabled := range []bool{false, true} {
		engine, err := NewEngine(engines...)
		if err != nil {
			t.Fatal(err)
		}
		if enabled {
			engine.EnableMatchDetail()
		}
		frames, _ := engine.DetectContent(raw)
		seen := map[string]bool{}
		for _, f := range frames {
			for from := range f.Froms {
				name := from.String()
				seen[name] = true
				if !enabled && f.MatchDetail != nil {
					t.Errorf("%s from %s: detail %+v while disabled", f.Name, name, f.MatchDetail)
				}
				if enabled && len(f.Froms) == 1 && (f.MatchDetail == nil || !strings.Contains(strings.ToLower(string(raw)), strings.ToLower(f.MatchDetail.MatcherValue))) {
					t.Errorf("%s from %s: detail %+v is not in the response", f.Name, name, f.MatchDetail)
				}
			}
		}
		for _, name := range []string{"fingerprinthub", "wappalyzer", "goby"} {
			if !seen[name] {
				t.Errorf("no hit from %s", name)
			}
		}
	}
}
