package judge

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/chainreactors/fingers/common"
)

type answerProvider func(map[string]Question) map[string]Answer

func (answerProvider) ID() string { return "answer-provider" }

func (p answerProvider) Judge(_ context.Context, _ interface{}, questions map[string]Question) (map[string]Answer, error) {
	return p(questions), nil
}

type failVersionProvider struct{ *mock }

func (p failVersionProvider) Judge(ctx context.Context, state interface{}, questions map[string]Question) (map[string]Answer, error) {
	if _, ok := questions["version_0"]; ok {
		return nil, errors.New("version unavailable")
	}
	return p.mock.Judge(ctx, state, questions)
}

func TestTypedPrimitives(t *testing.T) {
	j := New(answerProvider(func(qs map[string]Question) map[string]Answer {
		out := map[string]Answer{}
		for key, q := range qs {
			switch q.Type {
			case TypeBinary:
				out[key] = Answer{Yes: 0.82}
			case TypeChoice:
				out[key] = Answer{Choice: "b", Confidence: 0.93}
			case TypeScore:
				out[key] = Answer{Score: 0.4}
			}
		}
		return out
	}))
	state := map[string]string{"title": "Example"}
	if p, err := j.Yes(context.Background(), state, "Is this a product?"); err != nil || p != 0.82 {
		t.Fatalf("yes = %v, %v", p, err)
	}
	if choice, confidence, err := j.Choose(context.Background(), state, "Pick", map[string]string{"a": "A", "b": "B"}); err != nil || choice != "b" || confidence != 0.93 {
		t.Fatalf("choose = %q %v, %v", choice, confidence, err)
	}
	if score, err := j.Score(context.Background(), state, "Rate", "low", "high"); err != nil || score != 0.4 {
		t.Fatalf("score = %v, %v", score, err)
	}
	if _, _, err := j.Choose(context.Background(), state, "Pick", map[string]string{"one": "only"}); err == nil {
		t.Fatal("accepted a choice with one option")
	}
	if _, err := New(answerProvider(func(map[string]Question) map[string]Answer { return nil })).Yes(context.Background(), state, "Missing"); err == nil {
		t.Fatal("missing provider answer was accepted")
	}
	if _, _, err := New(answerProvider(func(map[string]Question) map[string]Answer {
		return map[string]Answer{"choice": {Choice: "outside", Confidence: 0.9}}
	})).Choose(context.Background(), state, "Pick", map[string]string{"a": "A", "b": "B"}); err == nil {
		t.Fatal("unknown provider choice was accepted")
	}
}

func TestPublicResultsDoNotMutateHits(t *testing.T) {
	j := newJudge(newMock())
	frames := testFrames()
	before, _ := json.Marshal(frames)
	inspected, err := j.Inspect(context.Background(), []byte(bodyRaw), frames)
	if err != nil || !inspected["wordpress"].Judge.Rejected || inspected["prototype"] == nil {
		t.Fatalf("inspect = %v, %v", inspected, err)
	}
	refined, err := j.Refine(context.Background(), []byte(bodyRaw), frames)
	if err != nil || refined["wordpress"] != nil || refined["jenkins"].Version != "2.401.3" {
		t.Fatalf("refine = %v, %v", refined, err)
	}
	// The judgement is copied, not shared with the Inspect result.
	refined["nginx"].Judge.Primary = true
	if inspected["nginx"].Judge.Primary {
		t.Fatal("Refine and Inspect share a Judgement")
	}
	if after, _ := json.Marshal(frames); string(after) != string(before) {
		t.Fatalf("hits changed:\n%s\n%s", before, after)
	}
	version, err := j.Version(context.Background(), []byte(bodyRaw), frames["jenkins"])
	if err != nil || version != "2.401.3" || frames["jenkins"].Version != "" {
		t.Fatalf("version = %q, %v; input = %q", version, err, frames["jenkins"].Version)
	}
}

func TestRefineSecondRoundFailureIsAtomic(t *testing.T) {
	frames := testFrames()
	j := New(failVersionProvider{newMock()})
	accepted, err := j.Refine(context.Background(), []byte(bodyRaw), frames)
	if err == nil || accepted != nil {
		t.Fatalf("failed refinement = %v, %v", accepted, err)
	}
	for _, f := range frames {
		if f.Judge != nil || f.Version != "" {
			t.Fatalf("input changed after second round failed: %+v", f)
		}
	}
}

func TestUnknownAndBodyNameSuggestion(t *testing.T) {
	raw := []byte("HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n<title>Sign in</title><p>QuantumGate Portal account access</p>")
	j := New(answerProvider(func(qs map[string]Question) map[string]Answer {
		out := map[string]Answer{}
		for key, q := range qs {
			switch key {
			case "page_kind":
				out[key] = Answer{Choice: string(KindLogin)}
			case "generic":
				out[key] = Answer{Yes: 0.9}
			default:
				if strings.Contains(q.Instructions, "`QuantumGate Portal`") {
					out[key] = Answer{Yes: 0.95}
				} else {
					out[key] = Answer{Yes: 0.05}
				}
			}
		}
		return out
	}))
	names, err := j.SuggestNames(context.Background(), raw)
	if err != nil || len(names) != 1 || names[0] != "QuantumGate Portal" {
		t.Fatalf("body suggestions = %v, %v", names, err)
	}
	unknown, err := j.IsUnknownProduct(context.Background(), raw, nil)
	if err != nil || !unknown {
		t.Fatalf("unknown = %v, %v", unknown, err)
	}
	known := common.Frameworks{}
	f := common.NewFramework("QuantumGate Portal", common.FrameFromGUESS)
	f.Judge = &common.Judgement{Layer: LayerApplication}
	known.Add(f)
	unknown, err = j.IsUnknownProduct(context.Background(), raw, known)
	if err != nil || unknown {
		t.Fatalf("known application = %v, %v", unknown, err)
	}
}

func TestKnownCDNErrorPageIsNotUnknown(t *testing.T) {
	raw := []byte("HTTP/1.1 403 Forbidden\r\nServer: cloudflare\r\n\r\n<title>Just a moment...</title>")
	j := New(answerProvider(func(qs map[string]Question) map[string]Answer {
		out := map[string]Answer{}
		for key := range qs {
			if key == "page_kind" {
				out[key] = Answer{Choice: string(KindError)}
			} else {
				out[key] = Answer{Yes: 0.95}
			}
		}
		return out
	}))
	f := common.NewFramework("cloudflare", common.FrameFromFingers)
	f.Judge = &common.Judgement{Layer: LayerCDN}
	accepted := common.Frameworks{}
	accepted.Add(f)
	unknown, err := j.IsUnknownProduct(context.Background(), raw, accepted)
	if err != nil || unknown {
		t.Fatalf("known CDN error = %t, %v", unknown, err)
	}
}
