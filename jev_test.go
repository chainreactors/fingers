package fingers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/chainreactors/fingers/jev"
)

func TestRefineWithJev(t *testing.T) {
	engine, err := NewEngine(FingersEngine, WappalyzerEngine)
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte("HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n<title>Welcome to nginx!</title>")
	frames, _ := engine.DetectContent(raw)
	if _, err := engine.Refine(context.Background(), raw, frames); err != ErrJevNotAttached {
		t.Fatalf("want ErrJevNotAttached, got %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Questions map[string]jev.Question }
		json.NewDecoder(r.Body).Decode(&req)
		answers := map[string]jev.Answer{}
		for k := range req.Questions {
			switch {
			case strings.HasPrefix(k, "layer_"):
				answers[k] = jev.Answer{Choice: string(jev.LayerServer)}
			case k == "page_kind":
				answers[k] = jev.Answer{Choice: "default_install"}
			default:
				answers[k] = jev.Answer{Noul: 0.9, Choice: jev.NotStated}
			}
		}
		json.NewEncoder(w).Encode(jev.Response{Answers: answers})
	}))
	defer srv.Close()
	client, _ := jev.NewClient("k")
	client.Endpoint = srv.URL
	engine.AttachJev(client)
	page, err := engine.Refine(context.Background(), raw, frames)
	if err != nil {
		t.Fatal(err)
	}
	if page.Kind != "default_install" || !frames["nginx"].HasTag(jev.TagLayer+string(jev.LayerServer)) {
		t.Fatalf("kind %q, nginx %v", page.Kind, frames["nginx"].Tags)
	}
}
