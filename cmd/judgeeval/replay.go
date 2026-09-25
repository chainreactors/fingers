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
	"sort"
	"strings"
	"time"

	"github.com/chainreactors/fingers"
	"github.com/chainreactors/fingers/common"
	"github.com/chainreactors/fingers/judge"
	"github.com/chainreactors/fingers/judge/jev"
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
	AutoName bool     `json:"auto_name"`
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
type replayRow struct {
	ID          string            `json:"id"`
	URL         string            `json:"url"`
	SHA256      string            `json:"sha256"`
	Baseline    common.Frameworks `json:"baseline"`
	Refined     common.Frameworks `json:"refined,omitempty"`
	Rejected    []string          `json:"rejected,omitempty"`
	Duplicates  []string          `json:"duplicates,omitempty"`
	Added       []string          `json:"added,omitempty"`
	Filled      map[string]string `json:"filled_versions,omitempty"`
	Kind        judge.Kind        `json:"kind,omitempty"`
	Generic     bool              `json:"generic"`
	Unknown     bool              `json:"unknown"`
	Suggestions []string          `json:"suggestions,omitempty"`
	Err         string            `json:"error,omitempty"`
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

// Cache the full provider input, not a near-page signature, for evaluation.
type replayProvider struct {
	judge.Provider
	dir         string
	namespace   string
	offline     bool
	calls, hits int
}

func (p *replayProvider) Calibration() (float64, float64) {
	if c, ok := p.Provider.(judge.Calibrated); ok {
		return c.Calibration()
	}
	return .5, .9
}
func (p *replayProvider) Judge(ctx context.Context, state interface{}, qs map[string]judge.Question) (map[string]judge.Answer, error) {
	data, err := json.Marshal([]interface{}{p.ID(), p.namespace, state, qs})
	if err != nil {
		return nil, err
	}
	path := filepath.Join(p.dir, digest(data)+".json")
	var answers map[string]judge.Answer
	if cached, err := os.ReadFile(path); err == nil && json.Unmarshal(cached, &answers) == nil {
		p.hits++
		return answers, nil
	}
	if p.offline {
		return nil, fmt.Errorf("offline cache miss: %s", filepath.Base(path))
	}
	p.calls++
	answers, err = p.Provider.Judge(ctx, state, qs)
	if err == nil {
		if e := writeJSON(path, answers); e != nil {
			return nil, e
		}
	}
	return answers, err
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
func copyFrames(frames common.Frameworks) common.Frameworks {
	data, _ := json.Marshal(frames)
	var out common.Frameworks
	_ = json.Unmarshal(data, &out)
	return out
}
func findLabel(frames common.Frameworks, l productLabel) *common.Framework {
	names := append([]string{l.Product}, l.Aliases...)
	var found *common.Framework
	for _, name := range names {
		for _, f := range frames {
			if f != nil && judge.NormalizeName(f.Name) == judge.NormalizeName(name) {
				if found == nil || (found.Version == "" && f.Version != "") || (found.Version == f.Version && f.Name < found.Name) {
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

func replay(manifestPath, historyPath, providerName, endpoint, cacheDir, out string, rps float64, offline, maintain bool, libraryPath string) error {
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
	var provider judge.Provider
	tokens := func() int64 { return 0 }
	if offline {
		if providerName != "jev" {
			return fmt.Errorf("unknown provider %q", providerName)
		}
		// Only ID and calibration are used; cache misses never invoke this provider.
		provider, err = jev.New("offline-cache-only")
	} else {
		provider, tokens, err = newProvider(providerName, endpoint, &limited{tick: ticker.C})
	}
	if err != nil {
		return err
	}
	cached := &replayProvider{Provider: provider, dir: cacheDir, namespace: endpoint, offline: offline}
	j := judge.New(cached)
	j.Cache = nil
	engine, err := fingers.NewEngine(fingers.FingersEngine, fingers.FingerPrintEngine, fingers.EHoleEngine, fingers.GobyEngine, fingers.WappalyzerEngine)
	if err != nil {
		return err
	}
	if libraryPath != "" {
		if err := loadReplayLibrary(engine, libraryPath, out); err != nil {
			return err
		}
	}
	j.Known = judge.NewRetriever(engine.Names())
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
	rowFile, err := os.Create(filepath.Join(out, "rows.jsonl"))
	if err != nil {
		return err
	}
	defer rowFile.Close()
	be, ce, re := json.NewEncoder(baselineFile), json.NewEncoder(cleanedFile), json.NewEncoder(rowFile)
	rows := make([]replayRow, 0, len(m.Samples))
	started := time.Now()
	for _, s := range m.Samples {
		r := replayRow{ID: s.ID, URL: s.URL, SHA256: s.SHA256}
		if historyPath != "" {
			r.Baseline = copyFrames(history[s.ID].Frames)
		} else {
			r.Baseline, err = engine.DetectContent(s.raw)
			if err != nil {
				return err
			}
		}
		if err := be.Encode(baselineRecord{s.ID, s.SHA256, r.Baseline}); err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		err = cleanReplay(ctx, j, s, &r)
		cancel()
		if err != nil {
			r.Err = err.Error()
		} else if err := ce.Encode(baselineRecord{s.ID, s.SHA256, r.Refined}); err != nil {
			return err
		}
		if err := re.Encode(r); err != nil {
			return err
		}
		rows = append(rows, r)
		fmt.Fprintf(os.Stderr, "replay %d/%d %s: baseline=%d refined=%d error=%t\n", len(rows), len(m.Samples), s.ID, len(r.Baseline), len(r.Refined), r.Err != "")
	}
	generated, err := generateReplay(m, j, out)
	if err != nil {
		return err
	}
	summary := summarizeReplay(m, rows, generated)
	summary.Model = provider.ID()
	summary.Requests = cached.calls
	summary.CacheHits = cached.hits
	summary.InputTokens = tokens()
	summary.Seconds = time.Since(started).Seconds()
	summary.BaselineSource = "current_rules_on_saved_responses"
	if historyPath != "" {
		summary.BaselineSource = "historical_results"
	}
	if err := writeJSON(filepath.Join(out, "metrics.json"), summary); err != nil {
		return err
	}
	if err := writeReplayReport(filepath.Join(out, "report.md"), summary); err != nil {
		return err
	}
	fmt.Printf("saved %s\n", filepath.Join(out, "report.md"))
	if summary.Errors > 0 {
		return fmt.Errorf("%d failed rows; see rows.jsonl", summary.Errors)
	}
	if maintain {
		return maintainReplay(m, rows, generated, out, engine)
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
func cleanReplay(ctx context.Context, j *judge.Judge, s replaySample, r *replayRow) error {
	var err error
	r.Refined, err = j.Refine(ctx, s.raw, r.Baseline)
	if err != nil {
		return err
	}
	if r.Kind, r.Generic, err = j.Classify(ctx, s.raw); err != nil {
		return err
	}
	inspected, err := j.Inspect(ctx, s.raw, r.Baseline)
	if err != nil {
		return err
	}
	for _, f := range inspected {
		if f.Judge != nil && f.Judge.Rejected {
			r.Rejected = append(r.Rejected, f.Name)
		}
		if f.Judge != nil && f.Judge.Duplicate {
			r.Duplicates = append(r.Duplicates, f.Name)
		}
	}
	r.Filled = map[string]string{}
	for _, f := range r.Refined {
		before := findLabel(r.Baseline, productLabel{Product: f.Name})
		if before == nil {
			r.Added = append(r.Added, f.Name)
		}
		if f.Version != "" && (before == nil || before.Version == "") {
			r.Filled[f.Name] = f.Version
		}
	}
	r.Unknown, err = j.IsUnknownProduct(ctx, s.raw, r.Refined)
	if err != nil {
		return err
	}
	r.Suggestions, err = j.SuggestNames(ctx, s.raw)
	sort.Strings(r.Rejected)
	sort.Strings(r.Duplicates)
	sort.Strings(r.Added)
	return err
}
