package fingers

import (
	"context"
	"strings"
	"testing"

	"github.com/chainreactors/fingers/judge"
)

func TestRefineWithJudge(t *testing.T) {
	engine, err := NewEngine(FingersEngine, WappalyzerEngine)
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte("HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n<title>Welcome to nginx!</title>")
	frames, _ := engine.DetectContent(raw)
	if _, err := engine.Refine(context.Background(), raw, frames); err != ErrNoJudge {
		t.Fatalf("want ErrNoJudge, got %v", err)
	}

	engine.AttachJudge(judge.New(server{}))
	page, err := engine.Refine(context.Background(), raw, frames)
	if err != nil {
		t.Fatal(err)
	}
	if page.Kind != judge.KindDefault || judge.LayerOf(frames["nginx"]) != judge.LayerServer {
		t.Fatalf("kind %q, nginx %v", page.Kind, frames["nginx"].Tags)
	}
}

// server is a provider that judges every product present at the server layer.
type server struct{}

func (server) ID() string { return "test" }

func (server) Judge(ctx context.Context, state interface{}, questions map[string]judge.Question) (map[string]judge.Answer, error) {
	answers := map[string]judge.Answer{}
	for k := range questions {
		switch {
		case strings.HasPrefix(k, "layer_"):
			answers[k] = judge.Answer{Choice: string(judge.LayerServer)}
		case k == "page_kind":
			answers[k] = judge.Answer{Choice: string(judge.KindDefault)}
		default:
			answers[k] = judge.Answer{Yes: 0.9, Choice: "not_stated"}
		}
	}
	return answers, nil
}
