package jev

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/chainreactors/fingers/judge"
)

func TestProviderWireFormatAndRetry(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") != "Bearer k" {
			t.Errorf("auth header: %q", r.Header.Get("Authorization"))
		}
		if calls == 1 {
			w.WriteHeader(529)
			return
		}
		var req struct {
			Model     string
			Questions map[string]map[string]interface{}
		}
		json.NewDecoder(r.Body).Decode(&req)
		b, c := req.Questions["b"], req.Questions["c"]
		criteria, _ := c["criteria"].(map[string]interface{})
		if req.Model != DefaultModel || b["type"] != "noul" || c["type"] != "choice" || criteria["x"] != nil || criteria["y"] != "why" {
			t.Errorf("request: %+v", req)
		}
		w.Write([]byte(`{"model":"jev-1.13.0","answers":{"b":{"type":"noul","noul":0.9},"c":{"type":"choice","choice":"y","confidence":0.8}},"usage":{"input_tokens":10,"output_tokens":1}}`))
	}))
	defer srv.Close()

	p, _ := New("k")
	p.Endpoint = srv.URL
	answers, err := p.Judge(context.Background(), "state", map[string]judge.Question{
		"b": judge.Binary("?"),
		"c": judge.Choice("?", map[string]string{"x": "", "y": "why"}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 || answers["b"].Yes != 0.9 || answers["c"].Choice != "y" || p.InputTokens != 10 {
		t.Fatalf("calls=%d answers=%+v tokens=%d", calls, answers, p.InputTokens)
	}
	if j := judge.New(p); j.Threshold != 0.5 || j.VersionConfidence != 0.9 || p.ID() != "jev/jev-1.13.0" {
		t.Fatalf("calibration %v %v id %s", j.Threshold, j.VersionConfidence, p.ID())
	}
}
