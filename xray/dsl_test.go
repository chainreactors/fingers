package xray

import (
	"testing"

	"github.com/chainreactors/fingers/resources"
	"github.com/chainreactors/neutron/protocols"
	"github.com/chainreactors/utils/httputils"
)

func TestNginxDSLMatch(t *testing.T) {
	engine, err := NewXrayEngine(resources.XrayWebData)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	// Simulate a typical nginx response
	raw := []byte("HTTP/1.1 200 OK\r\nServer: nginx/1.16.1\r\nContent-Type: text/html\r\n\r\n<html><head><title>Welcome to CentOS</title></head><body>test</body></html>")

	resp := httputils.NewResponseWithRaw(raw)
	if resp == nil {
		t.Fatal("failed to parse raw response")
	}

	// Check what buildEvent produces
	event := buildEvent(resp, "<html><head><title>Welcome to CentOS</title></head><body>test</body></html>", len(raw))

	t.Logf("event keys:")
	for k, v := range event {
		t.Logf("  %s = %v", k, v)
	}

	// Check if server is in event
	if sv, ok := event["server"]; ok {
		t.Logf("server value: %q", sv)
	} else {
		t.Error("server key missing from event!")
	}

	// Now test full WebMatch
	frames := engine.WebMatch(raw)
	t.Logf("matched frames: %d", len(frames))
	for _, f := range frames {
		t.Logf("  %s", f.Name)
	}

	// Check specifically for nginx template
	found := false
	for _, tmpl := range engine.templates {
		if tmpl.Info.Name == "Nginx" || tmpl.Id == "f5-nginx" {
			t.Logf("found nginx template: id=%s name=%s", tmpl.Id, tmpl.Info.Name)
			for _, req := range tmpl.GetRequests() {
				if req.CompiledOperators == nil {
					t.Log("  no compiled operators!")
					continue
				}
				for mi, m := range req.CompiledOperators.Matchers {
					t.Logf("  matcher[%d]: type=%s part=%s words=%v dsl=%v", mi, m.Type, m.Part, m.Words, m.DSL)
					ok, matched := req.Match(event, m)
					t.Logf("    match result: %v %v", ok, matched)
				}
			}
			found = true
		}
	}
	if !found {
		t.Error("nginx template not found in engine!")
	}

	// Also manually test the DSL expression
	t.Log("\n--- Manual DSL test ---")
	testData := protocols.InternalEvent{
		"server": "nginx/1.16.1",
		"body":   "test",
	}
	t.Logf("manual server value: %q", testData["server"])
}
