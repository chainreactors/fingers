package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/chainreactors/utils/jev"

	"github.com/chainreactors/fingers/common"
	"github.com/chainreactors/fingers/judge"
	"github.com/chainreactors/fingers/judge/maintain"
)

func stringPtr(s string) *string { return &s }
func testFrames(name, version string) common.Frameworks {
	f := common.NewFrameworkWithVersion(name, common.FrameFromGUESS, version)
	out := common.Frameworks{}
	out.Add(f)
	return out
}
func TestReplayCountsErrorsAndUnlabelledSeparately(t *testing.T) {
	m := &replayManifest{Samples: []replaySample{{ID: "a", Group: "host-a", ContentSHA256: "a", Labels: []productLabel{{Product: "Apache", Present: true, Version: stringPtr("2.4.38")}, {Product: "nginx", Present: false}}}, {ID: "failed", Group: "host-b", ContentSHA256: "b", Labels: []productLabel{{Product: "Apache", Present: true}}}}}
	base := testFrames("nginx", "")
	after := testFrames("apache http server", "2.4.38")
	after.Add(common.NewFramework("unlabelled-library", common.FrameFromGUESS))
	r := record{ID: "a", Baseline: base, Judged: after}
	summary := summarizeReplay(m, []record{r, {ID: "failed", Err: "network"}}, nil, nil)
	if summary.Errors != 1 || summary.LabelledPairs != 2 || summary.Baseline.Detection.FP != 1 || summary.Baseline.Detection.FN != 1 || summary.Accepted.Detection.TP != 1 || summary.Accepted.Detection.TN != 1 || summary.Accepted.UnlabelledPredictions != 1 {
		t.Fatalf("metrics: %+v", summary)
	}
	if summary.NaturalMissesRecovered != 1 || summary.FalseHitsRemoved != 1 || summary.CorrectVersionFills != 1 {
		t.Fatalf("changes: %+v", summary)
	}
}
func TestReplayExactNamesDoNotCreditDifferentProducts(t *testing.T) {
	frames := testFrames("wordpress-woocommerce", "10.4.4")
	if findLabel(frames, productLabel{Product: "wordpress"}) != nil {
		t.Fatal("substring credited a different product")
	}
	if findLabel(frames, productLabel{Product: "WooCommerce", Aliases: []string{"wordpress-woocommerce"}}) == nil {
		t.Fatal("explicit alias not matched")
	}
}
func TestReplayAbstentionRequiresIdentifiedProduct(t *testing.T) {
	v := versionScore{}
	v.add(nil, "")
	v.add(common.NewFramework("nginx", common.FrameFromGUESS), "")
	v.add(common.NewFrameworkWithVersion("nginx", common.FrameFromGUESS, "1.2.3"), "")
	if v.ProductMissing != 1 || v.CorrectAbstentions != 1 || v.Unsupported != 1 {
		t.Fatalf("versions: %+v", v)
	}
}
func TestGenerationSplitRejectsLeakageAndContradictoryLabels(t *testing.T) {
	sample := func(id, group, hash string, present bool) replaySample {
		return replaySample{ID: id, Group: group, ContentSHA256: hash, Labels: []productLabel{{Product: "Caddy", Present: present}}}
	}
	m := &replayManifest{Samples: []replaySample{sample("train", "a", "one", true), sample("negative", "b", "two", false), sample("same-host", "a", "three", true), sample("same-response", "c", "one", true), sample("test", "d", "four", true), sample("duplicate-test", "e", "four", true), sample("test-negative", "f", "five", false)}}
	p := generationPlan{Name: "caddy", Product: "Caddy", Positive: []string{"train"}, Negative: []string{"negative"}}
	test, excluded, err := generationSplit(m, p)
	if err != nil || len(test) != 2 || len(excluded) != 3 {
		t.Fatalf("split test=%v excluded=%v err=%v", test, excluded, err)
	}
	p.Positive = []string{"negative"}
	if _, _, err := generationSplit(m, p); err == nil {
		t.Fatal("contradictory training truth accepted")
	}
}
func TestReplayValidatesResponseHashAndEvidence(t *testing.T) {
	dir := t.TempDir()
	raw := []byte("HTTP/1.1 200 OK\r\nServer: nginx/1.21.5\r\nContent-Length: 0\r\n\r\n")
	if err := os.WriteFile(filepath.Join(dir, "page.http"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	m := replayManifest{Schema: 1, Samples: []replaySample{{ID: "one", URL: "http://example.test/", Group: "example.test", CapturedAt: "2026-09-25T00:00:00Z", Response: "page.http", SHA256: digest(raw), Labels: []productLabel{{Product: "nginx", Present: true, Evidence: []string{"Server: nginx/1.21.5"}, Basis: "header"}}}}}
	path := filepath.Join(dir, "manifest.json")
	if err := writeJSON(path, m); err != nil {
		t.Fatal(err)
	}
	if _, err := loadReplay(path); err != nil {
		t.Fatal(err)
	}
	m.Samples[0].SHA256 = strings.Repeat("0", 64)
	_ = writeJSON(path, m)
	if _, err := loadReplay(path); err == nil {
		t.Fatal("changed response accepted")
	}
	m.Samples[0].SHA256 = digest(raw)
	m.Samples[0].Labels[0].Evidence = []string{"invented"}
	_ = writeJSON(path, m)
	if _, err := loadReplay(path); err == nil {
		t.Fatal("missing evidence accepted")
	}
}
func TestReplayConfinesResponsePaths(t *testing.T) {
	if _, err := confinedPath(t.TempDir(), "../secret.http"); err == nil {
		t.Fatal("outside path accepted")
	}
}

type replayTestProvider struct {
	calls int
	id    string
}

func (p *replayTestProvider) ID() string { return "test/replay/" + p.id }
func (p *replayTestProvider) Judge(_ context.Context, _ interface{}, qs map[string]jev.Claim) (map[string]jev.Ruling, error) {
	p.calls++
	answers := map[string]jev.Ruling{}
	for key := range qs {
		answers[key] = jev.Ruling{Option: "yes", Confidence: 1}
	}
	return answers, nil
}

func TestReplayOfflineNeverCallsProvider(t *testing.T) {
	provider := &replayTestProvider{}
	p := &recordingProvider{Provider: provider, dir: t.TempDir(), offline: true}
	qs := map[string]jev.Claim{"product": {Statement: "Is this nginx?", Options: map[string]jev.Option{"yes": {Outcome: jev.Holds}, "no": {Outcome: jev.Refuted}, jev.OptionInsufficient: {Outcome: jev.Insufficient}}}}
	ctx := context.Background()
	if _, err := p.Judge(ctx, "page", qs); err == nil || !strings.Contains(err.Error(), "offline cache miss") {
		t.Fatalf("expected offline cache miss: %v", err)
	}
	if provider.calls != 0 || p.calls != 0 {
		t.Fatal("offline cache miss called the provider")
	}
	p.offline = false
	if _, err := p.Judge(ctx, "page", qs); err != nil {
		t.Fatal(err)
	}
	p.offline = true
	if answers, err := p.Judge(ctx, "page", qs); err != nil || answers["product"].Option != "yes" {
		t.Fatalf("cached answer: %v %v", answers, err)
	}
	if _, err := p.Judge(ctx, "different page", qs); err == nil {
		t.Fatal("different state reused cached answer")
	}
	provider.id = "different-endpoint"
	if _, err := p.Judge(ctx, "page", qs); err == nil {
		t.Fatal("different endpoint reused cached answer")
	}
	if provider.calls != 1 || p.calls != 1 || p.hits != 1 {
		t.Fatalf("calls=%d requests=%d hits=%d", provider.calls, p.calls, p.hits)
	}
}

func TestReplayVersionFillsDeduplicateAliases(t *testing.T) {
	l := productLabel{Product: "PHP", Aliases: []string{"php-runtime"}, Present: true, Version: stringPtr("5.6.40")}
	m := &replayManifest{Samples: []replaySample{{ID: "a", Labels: []productLabel{l}}}}
	after := testFrames("PHP", "5.6.40")
	after.Add(common.NewFrameworkWithVersion("php-runtime", common.FrameFromGUESS, "5.6.40"))
	r := record{ID: "a", Baseline: testFrames("PHP", "5.6.40"), Judged: after}
	if s := summarizeReplay(m, []record{r}, nil, nil); s.VersionFills != 0 {
		t.Fatalf("existing alias version counted as new: %+v", s)
	}
	r.Baseline = testFrames("PHP", "")
	if s := summarizeReplay(m, []record{r}, nil, nil); s.VersionFills != 1 || s.CorrectVersionFills != 1 {
		t.Fatalf("alias fills counted twice: %+v", s)
	}
}

func TestReplayDiscoveryDoesNotRecoverDetections(t *testing.T) {
	m := &replayManifest{Samples: []replaySample{{ID: "a", Labels: []productLabel{{Product: "New API", Present: true}}}}}
	r := record{ID: "a"}
	clusters := []*maintain.Cluster{{Samples: []string{"a"}, Outcome: jev.Refuted, Candidates: []string{"Login", "New API"}}}
	s := summarizeReplay(m, []record{r}, nil, clusters)
	if s.MissedProductsDiscovered != 1 || s.NaturalMissesRecovered != 0 || s.Accepted.Detection.FN != 1 {
		t.Fatalf("discovery credited as detections: %+v", s)
	}
}

func TestReplaySnapshotIsSelfContained(t *testing.T) {
	raw := []byte("HTTP/1.1 200 OK\r\nServer: nginx/1.21.5\r\nContent-Length: 0\r\n\r\n")
	m := &replayManifest{Schema: 1, Samples: []replaySample{{ID: "a", URL: "http://example.test/", Group: "example.test", CapturedAt: "2026-09-25T00:00:00Z", Response: "unavailable/page.http", SHA256: digest(raw), raw: raw}}}
	dir := t.TempDir()
	if err := saveReplaySnapshot(dir, m); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadReplay(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(loaded.Samples[0].raw) != string(raw) || loaded.Samples[0].SHA256 != m.Samples[0].SHA256 {
		t.Fatal("snapshot response changed")
	}
	if m.Samples[0].Response != "unavailable/page.http" {
		t.Fatal("snapshot write mutated source manifest")
	}
}

func TestGenerationSplitRejectsSameHostnameAcrossGroups(t *testing.T) {
	m := &replayManifest{Samples: []replaySample{
		{ID: "positive", URL: "http://example.test/", Group: "one", ContentSHA256: "1", Labels: []productLabel{{Product: "Caddy", Present: true}}},
		{ID: "negative", URL: "http://negative.test/", Group: "two", ContentSHA256: "2", Labels: []productLabel{{Product: "Caddy", Present: false}}},
		{ID: "leak", URL: "https://EXAMPLE.test:443/another-page", Group: "three", ContentSHA256: "3", Labels: []productLabel{{Product: "Caddy", Present: true}}},
	}}
	plan := generationPlan{Name: "caddy", Product: "Caddy", Positive: []string{"positive"}, Negative: []string{"negative"}}
	test, excluded, err := generationSplit(m, plan)
	if err != nil || len(test) != 0 || len(excluded) != 1 || excluded[0] != "leak" {
		t.Fatalf("hostname leakage: test=%v excluded=%v error=%v", test, excluded, err)
	}
}

// Exercise both public CLI modes against one local Jev server, then replay
// offline from the exact same cache. Reports must explain the same evaluation.
func TestDirectoryAndReplayShareRecordAndCache(t *testing.T) {
	var calls int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&calls, 1)
		var req struct {
			Questions map[string]struct{ Criteria map[string]interface{} }
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		answers := map[string]map[string]interface{}{}
		for id, q := range req.Questions {
			option := jev.OptionInsufficient
			if _, ok := q.Criteria[judge.OptionRunning]; ok {
				option = judge.OptionRunning
			}
			answers[id] = map[string]interface{}{"choice": option, "confidence": 1}
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"answers": answers})
	}))
	defer srv.Close()
	t.Setenv(jev.EnvAPIKey, "local-test")
	root := t.TempDir()
	samples := filepath.Join(root, "samples")
	if err := os.Mkdir(samples, 0700); err != nil {
		t.Fatal(err)
	}
	raw := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<title>Jenkins</title><body>Jenkins <input name=\"j_username\"></body>")
	if err := os.WriteFile(filepath.Join(samples, "a.http"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	cache := filepath.Join(root, "cache")
	directory := filepath.Join(root, "directory")
	if err := run("jev", samples, "", cache, directory, srv.URL, 100, 2, 0); err != nil {
		t.Fatal(err)
	}
	readRow := func(dir string) record {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(dir, "rows.jsonl"))
		if err != nil {
			t.Fatal(err)
		}
		var r record
		if err := json.Unmarshal(data, &r); err != nil {
			t.Fatal(err)
		}
		var fields map[string]json.RawMessage
		_ = json.Unmarshal(data, &fields)
		for _, old := range []string{"refined", "filled_versions", "verdicts", "outcomes", "evidence", "rejected", "duplicates", "missing_candidates"} {
			if _, ok := fields[old]; ok {
				t.Fatalf("legacy field %s remains", old)
			}
		}
		return r
	}
	first := readRow(directory)
	if len(first.Judged) == 0 || atomic.LoadInt64(&calls) != 1 {
		t.Fatalf("expected one presence batch: frames=%d calls=%d", len(first.Judged), calls)
	}
	m := replayManifest{Schema: 1, Samples: []replaySample{{ID: "a.http", URL: "http://example.test/", Group: "example.test", CapturedAt: "2026-09-26T00:00:00Z", Response: "samples/a.http", SHA256: digest(raw)}}}
	manifest := filepath.Join(root, "manifest.json")
	if err := writeJSON(manifest, m); err != nil {
		t.Fatal(err)
	}
	replayDir := filepath.Join(root, "replay")
	if err := replay(manifest, "", "jev", srv.URL, cache, replayDir, 100, true, false, ""); err != nil {
		t.Fatal(err)
	}
	second := readRow(replayDir)
	a, _ := json.Marshal(first.Judged)
	b, _ := json.Marshal(second.Judged)
	if string(a) != string(b) || atomic.LoadInt64(&calls) != 1 {
		t.Fatal("replay disagrees or invoked backend")
	}
	for _, dir := range []string{directory, replayDir} {
		data, err := os.ReadFile(filepath.Join(dir, "metrics.json"))
		if err != nil {
			t.Fatal(err)
		}
		var summary replaySummary
		if err := json.Unmarshal(data, &summary); err != nil {
			t.Fatal(err)
		}
		if summary.Schema != 3 || summary.Errors != 0 {
			t.Fatalf("summary %+v", summary)
		}
	}
}

func TestLabelInputConvertsOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "labels.json")
	data := []byte(`{"old":{"keep":["nginx"],"drop":["wordpress"],"version":{"product":"nginx","value":"1.2.3"}},"new":[{"product":"Orion","aliases":["Orion-console"],"present":true}]}`)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	labels, err := loadLabels(path)
	if err != nil || len(labels["old"]) != 2 || labels["old"][0].Version == nil || *labels["old"][0].Version != "1.2.3" || len(labels["new"][0].Aliases) != 1 {
		t.Fatalf("labels=%v error=%v", labels, err)
	}
}

func TestReplayHandlesBaselineWithoutAttributes(t *testing.T) {
	frames := common.Frameworks{"nginx": {Name: "nginx"}}
	m := &replayManifest{Samples: []replaySample{{ID: "a", Labels: []productLabel{{Product: "nginx", Present: true, Version: stringPtr("")}}}}}
	summary := summarizeReplay(m, []record{{ID: "a", Baseline: frames, Judged: frames}}, nil, nil)
	if summary.Accepted.Versions.CorrectAbstentions != 1 || summary.Baseline.Detection.TP != 1 {
		t.Fatalf("summary %+v", summary)
	}
}
