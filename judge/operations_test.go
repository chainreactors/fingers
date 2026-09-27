package judge

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/chainreactors/fingers/common"
	"github.com/chainreactors/utils/jev"
)

type rulingProvider func(map[string]jev.Claim) map[string]jev.Ruling

func (rulingProvider) ID() string { return "ruling-provider" }

func (p rulingProvider) Judge(_ context.Context, _ interface{}, claims map[string]jev.Claim) (map[string]jev.Ruling, error) {
	return p(claims), nil
}

type failVersionProvider struct{ *mock }

func (p failVersionProvider) Judge(ctx context.Context, state interface{}, claims map[string]jev.Claim) (map[string]jev.Ruling, error) {
	if _, ok := claims["version_jenkins"]; ok {
		return nil, errors.New("version unavailable")
	}
	return p.mock.Judge(ctx, state, claims)
}

func TestPublicResultsDoNotMutateHits(t *testing.T) {
	m := newMock()
	m.presence["jenkins"] = OptionRunning
	j := New(m)
	frames := testFrames()
	before, _ := json.Marshal(frames)
	inspected, err := j.Inspect(context.Background(), []byte(bodyRaw), frames)
	if err != nil || !inspected["wordpress"].Judge.Rejected {
		t.Fatalf("inspect = %v, %v", inspected, err)
	}
	accepted, err := j.Inspect(context.Background(), []byte(bodyRaw), frames)
	accepted = accepted.Accepted()
	if err != nil || accepted["wordpress"] != nil || accepted["jenkins"].Version != "2.401.3" {
		t.Fatalf("accepted = %v, %v", accepted, err)
	}
	// The judgement is copied, not shared with the Inspect result.
	accepted["nginx"].Judge.Option = "changed"
	if inspected["nginx"].Judge.Option == "changed" {
		t.Fatal("Independent Inspect calls share a Judgement")
	}
	if after, _ := json.Marshal(frames); string(after) != string(before) {
		t.Fatalf("hits changed:\n%s\n%s", before, after)
	}
	version, err := j.Version(context.Background(), []byte(bodyRaw), frames["jenkins"])
	if err != nil || version != "2.401.3" || frames["jenkins"].Version != "" {
		t.Fatalf("version = %q, %v; input = %q", version, err, frames["jenkins"].Version)
	}
}

// A failed version round keeps the presence and leaves the input untouched.
func TestInspectVersionFailureKeepsPresence(t *testing.T) {
	frames := testFrames()
	m := newMock()
	m.presence["jenkins"] = OptionRunning
	accepted, err := New(failVersionProvider{m}).Inspect(context.Background(), []byte(bodyRaw), frames)
	accepted = accepted.Accepted()
	if err == nil || accepted["wordpress"] != nil || accepted["jenkins"] == nil || accepted["jenkins"].Version != "" {
		t.Fatalf("failed version round = %v, %v", accepted, err)
	}
	for _, f := range frames {
		if f.Judge != nil || f.Version != "" {
			t.Fatalf("input changed after the version round failed: %+v", f)
		}
	}
}

func TestInspectInvalidBatchIsNotPartlyApplied(t *testing.T) {
	j := New(rulingProvider(func(cs map[string]jev.Claim) map[string]jev.Ruling {
		out := map[string]jev.Ruling{}
		for id := range cs {
			out[id] = jev.Ruling{Option: OptionRunning, Confidence: 1}
		}
		out["presence_wordpress"] = jev.Ruling{Option: "invented", Confidence: 1}
		return out
	}))
	all, err := j.Inspect(context.Background(), []byte(jenkinsRaw), testFrames())
	if err == nil || all["wordpress"].Judge != nil || (all["apache tomcat"].Judge != nil && all["apache tomcat"].Judge.Outcome != "") || all["nginx"].Judge.Outcome != jev.Holds.String() {
		t.Fatalf("partially applied invalid batch: %v %v", all, err)
	}
}

func TestInspectReevaluatesAndCopiesInputs(t *testing.T) {
	m := newMock()
	j := New(m)
	frames := testFrames()
	f := frames["wordpress"]
	f.MatchDetail = &common.MatchDetail{MatcherValue: "WordPress"}
	f.Judge = &common.Judgement{Option: OptionRunning, Outcome: jev.Holds.String(), Evidence: []string{"old"}}
	before, _ := json.Marshal(frames)
	all, err := j.Inspect(context.Background(), []byte(jenkinsRaw), frames)
	if err != nil || !all["wordpress"].Judge.Rejected {
		t.Fatalf("old judgement reused: %v %v", all, err)
	}
	all["wordpress"].MatchDetail.MatcherValue = "changed"
	all["wordpress"].Tags = append(all["wordpress"].Tags, "changed")
	all["wordpress"].Froms[common.FrameFromFingers] = true
	all["wordpress"].Version = "changed"
	all["wordpress"].Judge.Evidence[0] = "changed"
	after, _ := json.Marshal(frames)
	if string(before) != string(after) {
		t.Fatal("result mutated input")
	}
	partial, err := j.Inspect(context.Background(), []byte("not HTTP"), frames)
	if err == nil || len(partial) != len(frames) || partial["wordpress"].Judge != nil {
		t.Fatalf("parse failure lost baseline: %v %v", partial, err)
	}
	partial["wordpress"].MatchDetail.MatcherValue = "also changed"
	if frames["wordpress"].MatchDetail.MatcherValue != "WordPress" {
		t.Fatal("parse-error baseline shares pointers")
	}
	copied := cloneFramework(f)
	copied.Judge.Evidence[0] = "changed"
	if f.Judge.Evidence[0] != "old" {
		t.Fatal("clone shares judgement evidence")
	}
}
