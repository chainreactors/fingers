package judge

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/chainreactors/fingers/common"
	"github.com/chainreactors/utils/jev"
)

func TestInspect(t *testing.T) {
	m := newMock()
	j := New(jev.Cached(m, jev.DefaultCacheSize))
	all, err := j.Inspect(context.Background(), []byte(jenkinsRaw), testFrames())
	if err != nil {
		t.Fatal(err)
	}
	if w := all["wordpress"].Judge; w == nil || !w.Rejected || w.Option != OptionMentioned || w.Outcome != "refuted" || len(w.Evidence) == 0 || !strings.Contains(w.Evidence[0], "WordPress") {
		t.Errorf("text-only wordpress not rejected on its evidence: %+v", w)
	}
	for _, name := range []string{"nginx", "jenkins"} {
		if v := all[name].Judge; v.Rejected || v.Option != OptionDeclared || v.Outcome != "holds" {
			t.Errorf("%s named in a header must be declared: %+v", name, v)
		}
	}
	if h := all["hsts"].Judge; !h.Rejected || h.Option != OptionAbsent || h.Outcome != "refuted" {
		t.Errorf("hsts without the header must be absent: %+v", h)
	}
	if all["apache tomcat"].Judge.Duplicate == all["apache-tomcat"].Judge.Duplicate {
		t.Errorf("exactly one tomcat spelling must be a dup")
	}
	// Facts are not asked: only wordpress and tomcat are claims.
	if len(m.requests) != 1 || strings.Join(m.requests[0], ",") != "presence_apachetomcat,presence_wordpress" {
		t.Fatalf("requests: %v", m.requests)
	}
	claims, _ := json.Marshal(m.lastState["matches"])
	if !strings.Contains(string(claims), "We moved here from WordPress") {
		t.Errorf("claim evidence missing from the state: %s", claims)
	}

	accepted, err := j.Inspect(context.Background(), []byte(jenkinsRaw), testFrames())
	accepted = accepted.Accepted()
	if err != nil {
		t.Fatal(err)
	}
	if len(accepted) != 3 { // nginx, jenkins, tomcat
		t.Errorf("accepted: %v", accepted)
	}
	// Both versions are bound by name in the headers: taken without asking.
	if accepted["jenkins"].Version != "2.401.3" || accepted["nginx"].Version != "1.24.0" {
		t.Errorf("versions: jenkins %q nginx %q", accepted["jenkins"].Version, accepted["nginx"].Version)
	}
	// The presence come from the cache; tomcat is offered no version, since
	// both strings are bound by name to other products.
	if len(m.requests) != 1 {
		t.Errorf("cached presence were asked again: %v", m.requests)
	}
}

// DropInsufficient decides what an undecided claim does; a ruling below
// MinConfidence is undecided whatever it chose.
func TestInsufficient(t *testing.T) {
	for _, c := range []struct {
		on         bool
		confidence float64
		option     string
		rejected   bool
	}{
		{false, 0.95, OptionRunning, false},
		{false, 0.2, jev.OptionInsufficient, false},
		{true, 0.2, jev.OptionInsufficient, true},
		{true, 0.95, OptionRunning, false},
	} {
		m := newMock()
		m.confidence = c.confidence
		j := New(jev.Cached(m, jev.DefaultCacheSize))
		j.DropInsufficient = c.on
		all, err := j.Inspect(context.Background(), []byte(jenkinsRaw), testFrames())
		if err != nil {
			t.Fatal(err)
		}
		tomcat := all["apache tomcat"].Judge
		if all["apache-tomcat"].Judge.Duplicate {
			tomcat = all["apache-tomcat"].Judge
		}
		outcome := "holds"
		if c.option == jev.OptionInsufficient {
			outcome = "insufficient"
		}
		if tomcat.Option != OptionRunning || tomcat.Outcome != outcome || tomcat.Rejected != c.rejected {
			t.Errorf("%+v: tomcat %+v", c, tomcat)
		}
	}
}

// A failed provider leaves the input untouched, and the result still holds
// what code established: duplicates merged, header facts decided, the
// undecided hits kept unjudged.
func TestFailedProviderKeepsFacts(t *testing.T) {
	m := newMock()
	m.fail = true
	frames := testFrames()
	before, _ := json.Marshal(frames)
	accepted, err := New(m).Inspect(context.Background(), []byte(jenkinsRaw), frames)
	accepted = accepted.Accepted()
	if err == nil {
		t.Fatal("expected error")
	}
	if after, _ := json.Marshal(frames); string(after) != string(before) {
		t.Fatalf("frames changed on failure:\n%s\n%s", before, after)
	}
	// nginx, jenkins (declared), wordpress and one tomcat (unjudged); hsts absent, one tomcat a duplicate.
	if len(accepted) != 4 || accepted["hsts"] != nil || accepted["wordpress"] == nil || accepted["wordpress"].Judge != nil ||
		accepted["jenkins"].Judge.Option != OptionDeclared {
		t.Fatalf("accepted on failure: %v", accepted)
	}
}

func TestRepeatedInspectIsCacheable(t *testing.T) {
	m := newMock()
	m.presence["jenkins"] = OptionRunning
	j := New(jev.Cached(m, jev.DefaultCacheSize))
	for i := 0; i < 2; i++ {
		accepted, err := j.Inspect(context.Background(), []byte(bodyRaw), testFrames())
		accepted = accepted.Accepted()
		if err != nil {
			t.Fatal(err)
		}
		if accepted["jenkins"].Version != "2.401.3" {
			t.Fatalf("run %d: cached rulings not applied", i)
		}
	}
	if m.calls != 2 {
		t.Fatalf("calls=%d", m.calls)
	}
}

// Versions are ordered by their resolved outcome.
func TestVersionOrder(t *testing.T) {
	frames := common.Frameworks{}
	for name, j := range map[string]*common.Judgement{"jquery": {Option: jev.OptionInsufficient}, "apache": {Option: OptionDeclared, Outcome: jev.Holds.String()},
		"gitlab": {Option: OptionRunning, Outcome: jev.Holds.String()}, "unjudged": nil} {
		f := common.NewFramework(name, common.FrameFromFingers)
		f.Judge = j
		frames.Add(f)
	}
	var got []string
	for _, f := range versionOrder(frames) {
		got = append(got, f.Name)
	}
	if strings.Join(got, ",") != "apache,gitlab,jquery,unjudged" {
		t.Fatalf("order: %v", got)
	}
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

// Versions stated only in the body are picked by the provider, all kept
// products in one request, each from its own candidates.
func TestInspectVersionsEveryProduct(t *testing.T) {
	m := newMock()
	m.presence["jenkins"] = OptionRunning
	accepted, err := New(m).Inspect(context.Background(), []byte(bodyRaw), testFrames())
	accepted = accepted.Accepted()
	if err != nil {
		t.Fatal(err)
	}
	if accepted["jenkins"].Version != "2.401.3" || accepted["nginx"].Version != "1.24.0" {
		t.Fatalf("versions: jenkins %q nginx %q", accepted["jenkins"].Version, accepted["nginx"].Version)
	}
	if len(m.requests) != 2 || !strings.HasPrefix(strings.Join(m.requests[1], ","), "version_apachetomcat,version_jenkins") {
		t.Fatalf("requests: %v", m.requests)
	}
	if _, ok := m.lastState["version_strings"]; !ok {
		t.Errorf("version strings not in the state: %v", m.lastState)
	}
}

func TestVersionNeedsConfidence(t *testing.T) {
	m := newMock()
	m.presence["jenkins"] = OptionRunning
	m.confidence = 0.2
	accepted, err := New(m).Inspect(context.Background(), []byte(bodyRaw), testFrames())
	accepted = accepted.Accepted()
	if err != nil {
		t.Fatal(err)
	}
	if v := accepted["jenkins"].Version; v != "" {
		t.Fatalf("low-confidence version written: %q", v)
	}
}
