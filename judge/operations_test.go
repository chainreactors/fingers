package judge

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/chainreactors/fingers/common"
	"github.com/chainreactors/fingers/fingers"
)

type answerProvider func(map[string]Question) map[string]Answer

func (answerProvider) ID() string { return "answer-provider" }

func (p answerProvider) Judge(_ context.Context, _ interface{}, questions map[string]Question) (map[string]Answer, error) {
	return p(questions), nil
}

type failVersionProvider struct{ *mock }

func (p failVersionProvider) Judge(ctx context.Context, state interface{}, questions map[string]Question) (map[string]Answer, error) {
	if _, ok := questions["version"]; ok {
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
	j := New(newMock())
	frames := testFrames()
	inputJenkins := frames["jenkins"]
	accepted, err := j.Verify(context.Background(), []byte(jenkinsRaw), frames, "Prototype")
	if err != nil {
		t.Fatal(err)
	}
	if accepted["wordpress"] != nil || accepted["jenkins"] == nil || Judged(inputJenkins) {
		t.Fatalf("verify result/input: %v / %v", accepted, frames)
	}
	inspected, err := j.Inspect(context.Background(), []byte(jenkinsRaw), frames, "Prototype")
	if err != nil || !Is(inspected["wordpress"], Rejected) || Judged(frames["wordpress"]) {
		t.Fatalf("inspect result/input: %v / %v / %v", inspected, frames, err)
	}
	refined, kind, generic, err := j.Refine(context.Background(), []byte(jenkinsRaw), frames, "Prototype")
	if err != nil || kind != KindLogin || !generic || refined["jenkins"].Version != "2.401.3" {
		t.Fatalf("refine = %v %q %v, %v", refined, kind, generic, err)
	}
	if frames["jenkins"] != inputJenkins || inputJenkins.Version != "" || Judged(inputJenkins) {
		t.Fatal("Refine changed a rule hit")
	}
	version, err := j.Version(context.Background(), []byte(jenkinsRaw), inputJenkins)
	if err != nil || version != "2.401.3" || inputJenkins.Version != "" {
		t.Fatalf("version = %q, %v; input = %q", version, err, inputJenkins.Version)
	}
}

func TestRefineSecondRoundFailureIsAtomic(t *testing.T) {
	frames := testFrames()
	j := New(failVersionProvider{newMock()})
	accepted, kind, generic, err := j.Refine(context.Background(), []byte(jenkinsRaw), frames)
	if err == nil || accepted != nil || kind != "" || generic {
		t.Fatalf("failed refinement = %v %q %v, %v", accepted, kind, generic, err)
	}
	for _, f := range frames {
		if Judged(f) || f.Version != "" {
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
	setLayer(f, LayerApplication)
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
	setLayer(f, LayerCDN)
	accepted := common.Frameworks{}
	accepted.Add(f)
	unknown, err := j.IsUnknownProduct(context.Background(), raw, accepted)
	if err != nil || unknown {
		t.Fatalf("known CDN error = %t, %v", unknown, err)
	}
}

func TestGeneratorPassiveVersionAndValidation(t *testing.T) {
	positive1 := []byte("HTTP/1.1 200 OK\r\nServer: nginx/2.401.3\r\nX-Jenkins: 2.401.3\r\n\r\n<title>Jenkins</title>")
	positive2 := []byte("HTTP/1.1 200 OK\r\nServer: nginx/2.402.1\r\nX-Jenkins: 2.402.1\r\n\r\n<title>Jenkins</title>")
	negative := []byte("HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n<title>Blog</title><p>X-Jenkins: 9.9.9 release notes</p>")
	g := NewGenerator(nil).Name("Jenkins").PositiveVersion(positive1, "2.401.3").PositiveVersion(positive2, "2.402.1").Negative(negative)
	f, err := g.Generate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if f.Name != "Jenkins" || len(f.Rules) < 2 {
		t.Fatalf("fingerprint: %+v", f)
	}
	for _, sample := range []struct {
		raw     []byte
		version string
	}{{positive1, "2.401.3"}, {positive2, "2.402.1"}} {
		frame, _, ok := f.PassiveMatch(fingers.NewContent(sample.raw, "", true))
		if !ok || frame.Version != sample.version {
			t.Fatalf("version matcher = %+v, %v", frame, ok)
		}
	}
	compiled := len(f.Rules[0].Regexps.CompliedRegexp)
	if err := g.Validate(f); err != nil || len(f.Rules[0].Regexps.CompliedRegexp) != compiled {
		t.Fatalf("Validate mutated compiled matcher: %v", err)
	}
	if err := g.Validate(&fingers.Finger{Name: "Jenkins", Rules: fingers.Rules{&fingers.Rule{Regexps: &fingers.Regexps{Body: []string{"jenkins"}}}}}); err == nil {
		t.Fatal("validator accepted rule matching negative sample")
	}
}

func TestGeneratorActiveAndProbeWith(t *testing.T) {
	base := []byte("HTTP/1.1 200 OK\r\n\r\n<title>Login</title>")
	request := []byte("/admin")
	positive := []byte("HTTP/1.1 200 OK\r\nX-Orion: console\r\n\r\nOrion console")
	negative := []byte("HTTP/1.1 404 Not Found\r\n\r\nmissing")
	g := NewGenerator(nil).Name("Orion").Positive(base)
	if err := g.ProbeWith(context.Background(), request, func(_ context.Context, got []byte) ([]byte, error) {
		if !bytes.Equal(got, request) {
			return nil, errors.New("wrong request")
		}
		return positive, nil
	}); err != nil {
		t.Fatal(err)
	}
	g.Negative(base).Probe(request, negative)
	f, err := g.Generate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Rules) != 1 || f.Rules[0].SendDataStr != string(request) || !f.IsActive {
		t.Fatalf("active rule: %+v", f)
	}
	if err := g.Validate(f); err != nil {
		t.Fatal(err)
	}
	if len(f.Rules[0].Regexps.CompliedRegexp) != 0 {
		t.Fatal("Validate changed compiled rules")
	}
	if _, err := NewGenerator(nil).Name("Orion").Positive(base).Probe(request, positive).Negative(base).Generate(context.Background()); err == nil {
		t.Fatal("generated active rule without a negative probe")
	}
}

func TestGeneratorSelectsNameByDefault(t *testing.T) {
	positive := []byte("HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n<title>Orion</title><p>Orion console</p>")
	negative := []byte("HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n<title>Other</title>")
	j := New(answerProvider(func(qs map[string]Question) map[string]Answer {
		out := map[string]Answer{}
		for key, q := range qs {
			if strings.Contains(q.Instructions, "`Orion`") {
				out[key] = Answer{Yes: 0.95}
			} else {
				out[key] = Answer{Yes: 0.05}
			}
		}
		return out
	}))
	f, err := NewGenerator(j).Positive(positive).Negative(negative).Generate(context.Background())
	if err != nil || f.Name != "Orion" {
		t.Fatalf("auto name = %+v, %v", f, err)
	}
}

func TestGeneratorActiveVersion(t *testing.T) {
	base := []byte("HTTP/1.1 200 OK\r\n\r\n<title>Login</title>")
	request := []byte("/version")
	positive := []byte("HTTP/1.1 200 OK\r\nX-Orion: 3.1.2\r\n\r\nversion")
	negative := []byte("HTTP/1.1 200 OK\r\n\r\nnot installed")
	g := NewGenerator(nil).Name("Orion").PositiveVersion(base, "3.1.2").Probe(request, positive).Negative(base).Probe(request, negative)
	f, err := g.Generate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	frame, _, ok := f.ActiveMatch(2, func(got []byte) ([]byte, bool) { return positive, bytes.Equal(got, request) })
	if !ok || frame.Version != "3.1.2" {
		t.Fatalf("active version = %+v, %v", frame, ok)
	}
}

func TestGeneratorCoversDifferentPositiveVariants(t *testing.T) {
	base := "HTTP/1.1 200 OK\r\n%s\r\n<title>Welcome</title>"
	first := []byte(fmt.Sprintf(base, "X-Orion-Instance: ready\r\n"))
	second := []byte(fmt.Sprintf(base, "X-Orion-Service: yes\r\n"))
	other := []byte(fmt.Sprintf(base, "Server: nginx\r\n"))
	g := NewGenerator(nil).Name("Orion").Positive(first).Positive(second).Negative(other)
	f, err := g.Generate(context.Background())
	if err != nil || len(f.Rules) != 2 {
		t.Fatalf("variant rules = %+v, %v", f, err)
	}
}
