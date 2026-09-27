package maintain

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/chainreactors/fingers/common"
	"github.com/chainreactors/fingers/judge"
	"github.com/chainreactors/utils/jev"
)

func judged(name string, from common.From, verdict string, outcome jev.Outcome, detail *common.MatchDetail) *common.Framework {
	f := common.NewFramework(name, from)
	f.Judge = &common.Judgement{Verdict: verdict, Outcome: outcome.String()}
	f.MatchDetail = detail
	return f
}

func TestLedgerReportsJunkRules(t *testing.T) {
	l := NewLedger()
	webp := &common.MatchDetail{RuleIndex: 2, MatcherValue: "webp"}
	for i := 0; i < 4; i++ {
		fs := common.Frameworks{}
		fs.Add(judged("webp_server_go", common.FrameFromFingers, judge.OptionUnrelated, jev.Refuted, webp))
		fs.Add(judged("nginx", common.FrameFromGoby, judge.OptionDeclared, jev.Holds, nil))
		verdict, outcome := judge.OptionMentioned, jev.Refuted
		if i == 0 {
			verdict, outcome = judge.OptionRunning, jev.Holds
		}
		fs.Add(judged("git", common.FrameFromEhole, verdict, outcome, nil))
		fs.Add(common.NewFramework("unjudged", common.FrameFromGoby))
		l.Add(fmt.Sprintf("page%d", i), fs)
	}
	got := l.Report(3, 0.5)
	if len(got) != 2 || got[0].Name != "webp_server_go" || got[0].Matcher != "webp" || got[0].Rule != 2 || got[0].Engine != "fingers" ||
		got[1].Name != "git" || got[1].Engine != "ehole" || got[1].RefutedFraction() != 0.75 || len(got[1].Samples[jev.Refuted]) != 3 || got[1].Options[judge.OptionMentioned] != 3 {
		t.Fatalf("report: %+v", got)
	}
}

// coverer rules every coverage claim with one option.
type coverer string

func (coverer) ID() string { return "coverer" }

func (c coverer) Judge(_ context.Context, _ interface{}, qs map[string]jev.Claim) (map[string]jev.Ruling, error) {
	out := map[string]jev.Ruling{}
	for k := range qs {
		out[k] = jev.Ruling{Option: string(c), Confidence: 0.9}
	}
	return out, nil
}

func TestDiscoverClaimsCoverageOfPagesSharedByHosts(t *testing.T) {
	orion := func(host string) []byte {
		return []byte("HTTP/1.1 200 OK\r\nServer: nginx\r\nX-Orion-Node: " + host + "\r\n\r\n<title>Orion Console</title>" +
			`<script src="/static/orion.3f9a1c2b.js"></script><link rel="stylesheet" href="/static/orion.css?v=` + host + `">` +
			`<input name="username"><input name="password" type="password"><p>Welcome to Orion on ` + host + `</p>`)
	}
	blog := []byte("HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n<title>My Blog</title><script src=\"/wp-includes/js/jquery.js\"></script><p>Hello</p>")
	nginx := common.Frameworks{}
	nginx.Add(common.NewFramework("nginx", common.FrameFromFingers))
	var samples []Sample
	for _, h := range []string{"a.example", "b.example", "c.example"} {
		samples = append(samples, Sample{ID: h, Host: h, Raw: orion(h), Accepted: nginx})
	}
	samples = append(samples, Sample{ID: "blog", Host: "blog.example", Raw: blog, Accepted: nginx})

	clusters, err := Discover(context.Background(), judge.New(coverer(CoverageMissing)), samples, 2)
	if err != nil {
		t.Fatal(err)
	}
	c := clusters[0]
	if len(clusters) != 1 || c.Hosts != 3 || c.Outcome != jev.Refuted || len(c.Reported) != 1 || c.Reported[0] != "nginx" {
		t.Fatalf("clusters: %+v", clusters)
	}
	// Code, not the provider, offers the names a person picks from.
	found := false
	for _, n := range c.Candidates {
		found = found || n == "Orion Console"
	}
	if !found {
		t.Fatalf("candidates: %v", c.Candidates)
	}
	clusters, err = Discover(context.Background(), judge.New(coverer(CoverageExplained)), samples, 2)
	if err != nil || len(clusters) != 1 || clusters[0].Outcome != jev.Holds {
		t.Fatalf("explained: %+v %v", clusters, err)
	}
}

// Pages that share only the security headers any stack sets are not one page.
func TestDiscoverIgnoresCommonHeaders(t *testing.T) {
	head := "HTTP/1.1 200 OK\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nX-Request-Id: 1\r\n\r\n"
	samples := []Sample{
		{ID: "a", Host: "a.example", Raw: []byte(head + "<title>请通过官方域名访问</title>")},
		{ID: "b", Host: "b.example", Raw: []byte(head + "<title>Privacy Redirect</title>")},
	}
	clusters, err := Discover(context.Background(), judge.New(coverer(CoverageMissing)), samples, 2)
	if err != nil || len(clusters) != 0 {
		t.Fatalf("clusters: %+v %v", clusters, err)
	}
}

func TestLedgerReportIsDeepSnapshot(t *testing.T) {
	l := NewLedger()
	f := judged("one", common.FrameFromFingers, judge.OptionRunning, jev.Holds, nil)
	fs := common.Frameworks{"one": f}
	l.Add("a", fs)
	first := l.Report(1, 0)
	l.Add("b", fs)
	if first[0].Hits() != 1 || first[0].Outcomes["holds"] != 1 || len(first[0].Samples["holds"]) != 1 {
		t.Fatal("snapshot changed after Add")
	}
	first[0].Samples["holds"][0] = "changed"
	first[0].Options[judge.OptionRunning] = 99
	first[0].Outcomes["holds"] = 99
	second := l.Report(1, 0)
	if second[0].Samples["holds"][0] != "a" || second[0].Outcomes["holds"] != 2 || second[0].Options[judge.OptionRunning] != 2 {
		t.Fatal("snapshot mutation changed ledger")
	}
}

func TestClusterSnapshotKeepsRawChoiceAndResolvedOutcome(t *testing.T) {
	raw := []byte("HTTP/1.1 200 OK\r\n\r\n<title>Orion Console</title>")
	j := judge.New(coverer(CoverageMissing))
	j.MinConfidence = 1
	clusters, err := Discover(context.Background(), j, []Sample{{ID: "a", Host: "one", Raw: raw}, {ID: "b", Host: "two", Raw: raw}}, 2)
	if err != nil || len(clusters) != 1 {
		t.Fatalf("%v %v", clusters, err)
	}
	c := clusters[0]
	if c.Coverage.Option != CoverageMissing || c.Outcome != jev.Insufficient {
		t.Fatalf("raw choice lost: %+v", c)
	}
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var restored Cluster
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatal(err)
	}
	if restored.Samples[0] != "a" || restored.Samples[1] != "b" || restored.Coverage != c.Coverage || restored.Outcome != c.Outcome {
		t.Fatalf("snapshot: %+v", restored)
	}
}
