package fingers

import (
	"context"
	"strings"
	"testing"

	"github.com/chainreactors/fingers/judge"
	"github.com/chainreactors/utils/jev"
)

func TestInspectWithJudge(t *testing.T) {
	engine, err := NewEngine(FingersEngine, WappalyzerEngine)
	if err != nil {
		t.Fatal(err)
	}
	engine.EnableMatchDetail()
	raw := []byte("HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n<title>Welcome to nginx!</title>")
	frames, _ := engine.DetectContent(raw)
	j := judge.New(running{})
	accepted, err := j.Inspect(context.Background(), raw, frames)
	accepted = accepted.Accepted()
	if err != nil {
		t.Fatal(err)
	}
	if nginx := accepted["nginx"]; nginx == nil || nginx.Judge == nil || nginx.Judge.Option != judge.OptionDeclared || frames["nginx"].Judge != nil {
		t.Fatalf("accepted %v, input %v", accepted["nginx"], frames["nginx"])
	}
}

// running is a provider that judges every claim running and states no version.
type running struct{}

func (running) ID() string { return "test" }

func (running) Judge(ctx context.Context, state interface{}, claims map[string]jev.Claim) (map[string]jev.Ruling, error) {
	rulings := map[string]jev.Ruling{}
	for k := range claims {
		switch {
		case strings.HasPrefix(k, "presence_"):
			rulings[k] = jev.Ruling{Option: judge.OptionRunning, Confidence: 0.9}
		default:
			rulings[k] = jev.Ruling{Option: "not_stated", Confidence: 0.9}
		}
	}
	return rulings, nil
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
