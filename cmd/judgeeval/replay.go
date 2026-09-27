package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	"github.com/chainreactors/fingers"
	"github.com/chainreactors/fingers/common"
	"github.com/chainreactors/fingers/judge"
	"github.com/chainreactors/fingers/judge/maintain"
	"github.com/chainreactors/utils/jev"
)

// Labels are evidence for evaluation only; they are never passed to Judge.
type productLabel struct {
	Product  string   `json:"product"`
	Aliases  []string `json:"aliases,omitempty"`
	Present  bool     `json:"present"`
	Version  *string  `json:"version,omitempty"` // nil = not labelled, "" = not stated
	Evidence []string `json:"evidence"`          // literal excerpts in the saved response
	Basis    string   `json:"basis"`             // what the excerpt establishes
}
type replaySample struct {
	ID            string            `json:"id"`
	URL           string            `json:"url"`
	Group         string            `json:"group"`
	CapturedAt    string            `json:"captured_at"`
	Response      string            `json:"response"`
	SHA256        string            `json:"sha256"`
	ContentSHA256 string            `json:"content_sha256"`
	Labels        []productLabel    `json:"labels"`
	Probes        map[string]string `json:"probes,omitempty"` // send_data -> another sample ID
	raw           []byte
}
type generationPlan struct {
	Name     string   `json:"name"`
	Product  string   `json:"product"`
	Positive []string `json:"positive"`
	Negative []string `json:"negative"`
	Probe    string   `json:"probe,omitempty"`
}
type replayManifest struct {
	Schema     int              `json:"schema"`
	Scope      string           `json:"scope"`
	Samples    []replaySample   `json:"samples"`
	Generation []generationPlan `json:"generation"`
}
type baselineRecord struct {
	ID     string            `json:"id"`
	SHA256 string            `json:"sha256"`
	Frames common.Frameworks `json:"frames"`
}

// record stores source results once; accepted products and all metrics are derived.
type record struct {
	ID       string            `json:"id"`
	URL      string            `json:"url"`
	SHA256   string            `json:"sha256"`
	Baseline common.Frameworks `json:"baseline"`
	Judged   common.Frameworks `json:"judged"`
	Err      string            `json:"error,omitempty"`
	RuleMs   float64           `json:"rule_ms"`
	JudgeMs  float64           `json:"judge_ms"`
}

func digest(b []byte) string { return fmt.Sprintf("%x", sha256.Sum256(b)) }
func writeJSON(path string, value interface{}) error {
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0600)
}
func confinedPath(root, name string) (string, error) {
	if name == "" || filepath.IsAbs(name) {
		return "", fmt.Errorf("expected relative response path: %q", name)
	}
	joined := filepath.Join(root, filepath.FromSlash(name))
	rel, err := filepath.Rel(root, joined)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("response escapes corpus: %q", name)
	}
	return joined, nil
}
func loadReplay(path string) (*replayManifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m replayManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	if m.Schema != 1 || len(m.Samples) == 0 {
		return nil, fmt.Errorf("manifest requires schema=1 and samples")
	}
	seen := map[string]bool{}
	for i := range m.Samples {
		s := &m.Samples[i]
		if s.ID == "" || seen[s.ID] {
			return nil, fmt.Errorf("empty or duplicate sample ID %q", s.ID)
		}
		seen[s.ID] = true
		u, err := url.Parse(s.URL)
		if err != nil || u.Hostname() == "" || s.Group == "" || s.CapturedAt == "" {
			return nil, fmt.Errorf("%s: URL, group and captured_at required", s.ID)
		}
		filename, err := confinedPath(filepath.Dir(path), s.Response)
		if err != nil {
			return nil, err
		}
		s.raw, err = os.ReadFile(filename)
		if err != nil {
			return nil, err
		}
		if len(s.raw) > 2<<20 || digest(s.raw) != s.SHA256 {
			return nil, fmt.Errorf("%s: size limit or SHA256 mismatch", s.ID)
		}
		resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(s.raw)), nil)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", s.ID, err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("%s: incomplete response: %w", s.ID, err)
		}
		// Recompute rather than trusting the manifest for split leakage checks.
		stable := http.Header{}
		for k, v := range resp.Header {
			switch strings.ToLower(k) {
			case "date", "set-cookie", "etag", "last-modified", "connection", "content-length", "transfer-encoding", "x-request-id":
				continue
			}
			stable[k] = v
		}
		head, _ := json.Marshal([]interface{}{resp.StatusCode, stable})
		s.ContentSHA256 = digest(append(head, body...))
		evidence := strings.ToLower(string(s.raw) + "\n" + string(body))
		keys := map[string]bool{}
		for _, l := range s.Labels {
			key := judge.NormalizeName(l.Product)
			if key == "" || keys[key] || l.Basis == "" || len(l.Evidence) == 0 || (!l.Present && l.Version != nil) {
				return nil, fmt.Errorf("%s: invalid/duplicate label %q", s.ID, l.Product)
			}
			keys[key] = true
			for _, excerpt := range l.Evidence {
				if strings.TrimSpace(excerpt) == "" || !strings.Contains(evidence, strings.ToLower(excerpt)) {
					return nil, fmt.Errorf("%s: label evidence missing for %s", s.ID, l.Product)
				}
			}
		}
	}
	for _, s := range m.Samples {
		for request, id := range s.Probes {
			if request == "" || !seen[id] {
				return nil, fmt.Errorf("%s: invalid probe %q", s.ID, request)
			}
		}
	}
	return &m, nil
}

func loadHistory(path string) (map[string]baselineRecord, error) {
	out := map[string]baselineRecord{}
	if path == "" {
		return out, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	scan := bufio.NewScanner(f)
	scan.Buffer(make([]byte, 4096), 16<<20)
	for scan.Scan() {
		var r baselineRecord
		if err := json.Unmarshal(scan.Bytes(), &r); err != nil {
			return nil, err
		}
		if _, ok := out[r.ID]; ok {
			return nil, fmt.Errorf("duplicate historical ID %s", r.ID)
		}
		out[r.ID] = r
	}
	return out, scan.Err()
}
func versionOf(f *common.Framework) string {
	if f == nil || f.Attributes == nil {
		return ""
	}
	return f.Version
}
func findLabel(frames common.Frameworks, l productLabel) *common.Framework {
	names := append([]string{l.Product}, l.Aliases...)
	var found *common.Framework
	for _, name := range names {
		for _, f := range frames {
			if f != nil && judge.NormalizeName(f.Name) == judge.NormalizeName(name) {
				if found == nil || (versionOf(found) == "" && versionOf(f) != "") || (versionOf(found) == versionOf(f) && f.Name < found.Name) {
					found = f
				}
			}
		}
	}
	return found
}
func labelFor(s replaySample, name string) (productLabel, bool) {
	key := judge.NormalizeName(name)
	for _, l := range s.Labels {
		for _, n := range append([]string{l.Product}, l.Aliases...) {
			if judge.NormalizeName(n) == key {
				return l, true
			}
		}
	}
	return productLabel{}, false
}

func replay(manifestPath, historyPath, providerName, endpoint, cacheDir, out string, rps float64, offline, audit bool, libraryPath string) error {
	if rps <= 0 || rps > 100 || math.IsNaN(rps) {
		return fmt.Errorf("rps must be in (0,100]")
	}
	m, err := loadReplay(manifestPath)
	if err != nil {
		return err
	}
	history, err := loadHistory(historyPath)
	if err != nil {
		return err
	}
	if historyPath != "" {
		for _, s := range m.Samples {
			if r, ok := history[s.ID]; !ok || r.SHA256 != s.SHA256 {
				return fmt.Errorf("%s: history missing or response hash differs", s.ID)
			}
		}
	}
	if _, err := os.Stat(out); err == nil {
		return fmt.Errorf("output directory exists: use a new run directory")
	}
	if err := os.MkdirAll(out, 0755); err != nil {
		return err
	}
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		return err
	}
	if err := saveReplaySnapshot(out, m); err != nil {
		return err
	}
	ticker := time.NewTicker(time.Duration(float64(time.Second) / rps))
	defer ticker.Stop()
	var provider jev.Provider
	tokens := func() int64 { return 0 }
	if offline {
		if providerName != "jev" {
			return fmt.Errorf("unknown provider %q", providerName)
		}
		// Cache misses never invoke this provider.
		p, e := jev.NewClient("offline-cache-only")
		err = e
		if p != nil && endpoint != "" {
			p.Endpoint = endpoint
		}
		provider = p
	} else {
		provider, tokens, err = newProvider(providerName, endpoint, &limited{tick: ticker.C})
	}
	if err != nil {
		return err
	}
	cached := &recordingProvider{Provider: provider, dir: cacheDir, offline: offline}
	j := newJudge(cached)
	engine, err := fingers.NewEngine(fingers.FingersEngine, fingers.FingerPrintEngine, fingers.EHoleEngine, fingers.GobyEngine, fingers.WappalyzerEngine)
	if err != nil {
		return err
	}
	if libraryPath != "" {
		if err := loadReplayLibrary(engine, libraryPath, out); err != nil {
			return err
		}
	}
	if engine.Fingers() != nil {
		engine.EnableMatchDetail() // claims quote what each rule matched
	}
	baselineFile, err := os.Create(filepath.Join(out, "baseline.jsonl"))
	if err != nil {
		return err
	}
	defer baselineFile.Close()
	cleanedFile, err := os.Create(filepath.Join(out, "cleaned.jsonl"))
	if err != nil {
		return err
	}
	defer cleanedFile.Close()
	be, ce := json.NewEncoder(baselineFile), json.NewEncoder(cleanedFile)
	ledger := maintain.NewLedger()
	rows := make([]record, 0, len(m.Samples))
	started := time.Now()
	for _, s := range m.Samples {
		r := record{ID: s.ID, URL: s.URL, SHA256: s.SHA256}
		ruleStart := time.Now()
		if historyPath != "" {
			r.Baseline = history[s.ID].Frames
		} else {
			r.Baseline, err = engine.DetectContent(s.raw)
			if err != nil {
				return err
			}
		}
		r.RuleMs = ms(time.Since(ruleStart))
		if err := be.Encode(baselineRecord{s.ID, s.SHA256, r.Baseline}); err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		err = judgeRecord(ctx, j, s.raw, &r)
		cancel()
		if err != nil {
			r.Err = err.Error()
		} else if err := ce.Encode(baselineRecord{s.ID, s.SHA256, r.Judged.Accepted()}); err != nil {
			return err
		}
		ledger.Add(s.ID, r.Judged)
		rows = append(rows, r)
		fmt.Fprintf(os.Stderr, "replay %d/%d %s: baseline=%d accepted=%d error=%t\n", len(rows), len(m.Samples), s.ID, len(r.Baseline), len(r.Judged.Accepted()), r.Err != "")
	}
	if err := writeRows(filepath.Join(out, "rows.jsonl"), rows); err != nil {
		return err
	}
	clusters, err := discoverReplay(m, j, rows, out)
	if err != nil {
		return err
	}
	generated, err := generateReplay(m, j, out)
	if err != nil {
		return err
	}
	summary := summarizeReplay(m, rows, generated, clusters)
	summary.Requests, summary.CacheHits, summary.Claims = cached.stats()
	summary.JunkRules = ledger.Report(3, 0.5)
	if err := writeJSON(filepath.Join(out, "ledger.json"), ledger.Report(1, 0)); err != nil {
		return err
	}
	summary.Model = provider.ID()
	summary.InputTokens = tokens()
	summary.Seconds = time.Since(started).Seconds()
	summary.BaselineSource = "current_rules_on_saved_responses"
	if historyPath != "" {
		summary.BaselineSource = "historical_results"
	}
	if err := writeJSON(filepath.Join(out, "metrics.json"), summary); err != nil {
		return err
	}
	if err := writeReplayReport(filepath.Join(out, "report.md"), summary, m); err != nil {
		return err
	}
	fmt.Printf("saved %s\n", filepath.Join(out, "report.md"))
	if summary.Errors > 0 {
		return fmt.Errorf("%d failed rows; see rows.jsonl", summary.Errors)
	}
	if audit {
		return maintainReplay(m, clusters, generated, out, engine)
	}
	return nil
}

// Keep the exact labelled inputs together with the output for offline replay.
func saveReplaySnapshot(out string, m *replayManifest) error {
	copy := *m
	copy.Samples = append([]replaySample(nil), m.Samples...)
	if err := os.MkdirAll(filepath.Join(out, "samples"), 0700); err != nil {
		return err
	}
	for i := range copy.Samples {
		s := &copy.Samples[i]
		s.Response = "samples/" + s.SHA256 + ".http"
		if err := os.WriteFile(filepath.Join(out, s.Response), s.raw, 0600); err != nil {
			return err
		}
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		if err := writeJSON(filepath.Join(out, "build.json"), info); err != nil {
			return err
		}
	}
	return writeJSON(filepath.Join(out, "manifest.json"), copy)
}
func judgeRecord(ctx context.Context, j *judge.Judge, raw []byte, r *record) error {
	started := time.Now()
	var err error
	r.Judged, err = j.Inspect(ctx, raw, r.Baseline)
	r.JudgeMs = ms(time.Since(started))
	if err != nil {
		r.Err = err.Error()
	}
	return err
}

func discoverReplay(m *replayManifest, j *judge.Judge, rows []record, out string) ([]*maintain.Cluster, error) {
	byID := map[string]record{}
	for _, r := range rows {
		byID[r.ID] = r
	}
	var samples []maintain.Sample
	for _, s := range m.Samples {
		r, ok := byID[s.ID]
		if !ok || r.Err != "" {
			continue
		}
		samples = append(samples, maintain.Sample{ID: s.ID, Host: sampleHost(s), Raw: s.raw, Accepted: r.Judged.Accepted()})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	clusters, err := maintain.Discover(ctx, j, samples, 2)
	if err != nil {
		return nil, err
	}
	return clusters, writeJSON(filepath.Join(out, "discovery.json"), clusters)
}

// Clusters carry sample IDs; rows do not duplicate cluster state.
func missingCandidates(clusters []*maintain.Cluster) map[string][]string {
	out := map[string][]string{}
	for _, c := range clusters {
		if c.Outcome == jev.Refuted {
			for _, id := range c.Samples {
				out[id] = c.Candidates
			}
		}
	}
	return out
}

// sampleHost is the host a sample was captured from: its group joins
// several addresses of one operator.
func sampleHost(s replaySample) string {
	if s.Group != "" {
		return s.Group
	}
	if u, err := url.Parse(s.URL); err == nil {
		return strings.ToLower(u.Hostname())
	}
	return s.URL
}

func writeRows(path string, rows []record) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, r := range rows {
		if err := enc.Encode(r); err != nil {
			return err
		}
	}
	return nil
}
