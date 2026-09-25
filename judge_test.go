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
	j := judge.New(server{})
	j.Known = judge.NewRetriever(engine.Names())
	accepted, err := j.Refine(context.Background(), raw, frames)
	if err != nil {
		t.Fatal(err)
	}
	kind, _, err := j.Classify(context.Background(), raw)
	if err != nil || kind != judge.KindDefault {
		t.Fatalf("kind %q, %v", kind, err)
	}
	if nginx := accepted["nginx"]; nginx == nil || nginx.Judge == nil || nginx.Judge.Layer != judge.LayerServer || frames["nginx"].Judge != nil {
		t.Fatalf("accepted %v, input %v", accepted["nginx"], frames["nginx"])
	}
	if len(engine.Names()) == 0 {
		t.Fatal("engine has no names")
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
		case k == "primary":
			answers[k] = judge.Answer{Choice: "none_of_these"}
		default:
			answers[k] = judge.Answer{Yes: 0.9, Choice: "not_stated"}
		}
	}
	return answers, nil
}
