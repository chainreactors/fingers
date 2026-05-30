package xray

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// TestHTTPActiveMatchConcurrentRace exercises HTTPActiveMatch from many
// goroutines that share a single engine (the way the SDK drives active
// probing across concurrent targets). HTTPActiveMatch mutates shared
// template state (req.SetHTTPClient on tmpl.RequestsHTTP) and runs the same
// tmpl.Execute concurrently, so this is expected to trip the race detector
// and/or a "concurrent map writes" fatal — which recover() cannot catch.
func TestHTTPActiveMatchConcurrentRace(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<center>nginx</center> Welcome to nginx!"))
	}))
	defer srv.Close()

	engine, err := NewXrayEngine(nil)
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	tmplJSON := []byte(`[{"id":"f5-nginx","info":{"name":"Nginx","severity":"info"},` +
		`"http":[{"method":"GET","path":["{{BaseURL}}/"],` +
		`"matchers":[{"type":"word","words":["nginx"]}]}]}]`)
	if err := engine.LoadFromJSON(tmplJSON); err != nil {
		t.Fatalf("load template: %v", err)
	}
	if engine.Len() == 0 {
		t.Fatalf("no templates loaded; cannot exercise active match")
	}

	transport := &http.Transport{DisableKeepAlives: true}
	const workers = 50
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			engine.HTTPActiveMatch(srv.URL, 1, transport, nil)
		}()
	}
	wg.Wait()
}
