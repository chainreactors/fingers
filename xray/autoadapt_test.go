package xray

import (
	"strings"
	"testing"

	// Opt into raw xray POC support for this test by registering the xray
	// converter. Production code does not import convert, so it is not linked
	// into normal builds of this package.
	_ "github.com/chainreactors/neutron/convert"
)

// TestLoadRawXrayPOC verifies the engine auto-adapts a raw xray POC (rule +
// expression schema) at load time — no pre-conversion step required.
func TestLoadRawXrayPOC(t *testing.T) {
	// A raw xray POC, expressed as the JSON map the engine ingests. It has
	// `rules`/`expression` rather than neutron's `http`/`matchers`.
	rawXray := []byte(`[{
		"name": "fingerprint-test--08cms",
		"transport": "http",
		"detail": {"fingerprint": {"name": "08Cms", "cpe": "dingdian_network:08cms"}},
		"rules": {
			"r0": {"expression": "response.body_string.contains(\"08cms\")"}
		},
		"expression": "r0()"
	}]`)

	engine, err := NewXrayEngine(nil)
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	if err := engine.LoadFromJSON(rawXray); err != nil {
		t.Fatalf("LoadFromJSON raw xray: %v", err)
	}
	if engine.Len() != 1 {
		t.Fatalf("expected 1 template loaded from raw xray poc, got %d", engine.Len())
	}

	resp := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>powered by 08cms</html>")
	frames := engine.WebMatch(resp)
	if len(frames) == 0 {
		t.Fatalf("expected raw xray poc to match, got no frameworks")
	}
	var found bool
	for _, f := range frames {
		if strings.EqualFold(f.Name, "08Cms") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected framework 08Cms, got %v", frames)
	}
}
