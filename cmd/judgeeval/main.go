// judgeeval evaluates saved HTTP responses through the same Inspect pipeline as SDK callers.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/chainreactors/fingers"
	"github.com/chainreactors/fingers/judge"
	"github.com/chainreactors/fingers/judge/maintain"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/utils/jev"
)

func main() {
	manifest := flag.String("manifest", "", "replay evidence manifest with labels and generation plans")
	history := flag.String("history", "", "optional baseline.jsonl from a previous replay")
	offline := flag.Bool("offline", false, "manifest replay using exact cached answers only; no provider requests")
	maintain := flag.Bool("maintain", false, "audit novel products and validate a native additive fingerprint library")
	library := flag.String("library", "", "existing local native YAML library to load before manifest replay")
	samples := flag.String("samples", "testdata/samples", "directory of raw HTTP responses (*.http)")
	labels := flag.String("labels", "", "optional ground truth (see testdata/labels.json)")
	provider := flag.String("provider", "jev", "judge provider: jev")
	cache := flag.String("cache", "judgecache", "directory caching answers")
	out := flag.String("out", "judgereport", "output directory")
	rps := flag.Float64("rps", 15, "max provider requests per second")
	flag.Float64Var(&minConfidence, "min-confidence", 0, "judge MinConfidence (0 = Jev default)")
	workers := flag.Int("workers", 16, "concurrent pages")
	limit := flag.Int("limit", 0, "only the first N samples (0 = all)")
	endpoint := flag.String("endpoint", "", "provider API endpoint (default: the provider's)")
	flag.Parse()
	logs.Log.SetLevel(logs.ErrorLevel)
	if *manifest != "" {
		if err := replay(*manifest, *history, *provider, *endpoint, *cache, *out, *rps, *offline, *maintain, *library); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if *offline || *maintain || *library != "" {
		fmt.Fprintln(os.Stderr, "-offline, -maintain and -library require -manifest")
		os.Exit(1)
	}
	if err := run(*provider, *samples, *labels, *cache, *out, *endpoint, *rps, *workers, *limit); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// newProvider builds a provider by name; add new providers here. tokens
// reports input tokens sent, where the provider counts them.
func newProvider(name, endpoint string, transport http.RoundTripper) (p jev.Provider, tokens func() int64, err error) {
	switch name {
	case "jev":
		jp, err := jev.NewClient("")
		if err != nil {
			return nil, nil, err
		}
		if endpoint != "" {
			jp.Endpoint = endpoint
		}
		jp.HTTP.Transport = transport
		return jp, func() int64 { return atomic.LoadInt64(&jp.InputTokens) }, nil
	}
	return nil, nil, fmt.Errorf("unknown provider %q", name)
}

func run(providerName, samples, labelsPath, cacheDir, out, endpoint string, rps float64, workers, limit int) error {
	if rps <= 0 || rps > 100 || math.IsNaN(rps) || workers < 1 {
		return fmt.Errorf("rps must be in (0,100] and workers positive")
	}
	files, err := filepath.Glob(filepath.Join(samples, "*.http"))
	if err != nil {
		return err
	}
	sort.Strings(files)
	if limit > 0 && len(files) > limit {
		files = files[:limit]
	}
	labels, err := loadLabels(labelsPath)
	if err != nil {
		return err
	}
	for _, dir := range []string{cacheDir, out} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}
	ticker := time.NewTicker(time.Duration(float64(time.Second) / rps))
	defer ticker.Stop()
	provider, tokens, err := newProvider(providerName, endpoint, &limited{tick: ticker.C})
	if err != nil {
		return err
	}
	cached := &recordingProvider{Provider: provider, dir: cacheDir}
	j := newJudge(cached)
	engine, err := fingers.NewEngine(fingers.FingersEngine, fingers.FingerPrintEngine, fingers.EHoleEngine, fingers.GobyEngine, fingers.WappalyzerEngine)
	if err != nil {
		return err
	}
	engine.EnableMatchDetail()
	ledger := maintain.NewLedger()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rows := make([]record, len(files))
	jobs := make(chan int)
	var wg sync.WaitGroup
	var fatal error
	var once sync.Once
	started := time.Now()
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				r, err := evaluatePage(ctx, engine, j, files[i])
				rows[i] = r
				ledger.Add(r.ID, r.Judged)
				var apiErr *jev.APIError
				if errors.As(err, &apiErr) && apiErr.Status == 401 {
					once.Do(func() { fatal = errors.New("unauthorized: check " + jev.EnvAPIKey); cancel() })
				}
			}
		}()
	}
dispatch:
	for i := range files {
		select {
		case jobs <- i:
		case <-ctx.Done():
			break dispatch
		}
	}
	close(jobs)
	wg.Wait()
	if fatal != nil {
		return fatal
	}
	if err := writeRows(filepath.Join(out, "rows.jsonl"), rows); err != nil {
		return err
	}
	m := &replayManifest{}
	for _, r := range rows {
		m.Samples = append(m.Samples, replaySample{ID: r.ID, Group: r.ID, ContentSHA256: r.SHA256, Labels: labels[r.ID]})
	}
	summary := summarizeReplay(m, rows, nil, nil)
	summary.Model, summary.BaselineSource = provider.ID(), "current_rules_on_saved_responses"
	summary.Requests, summary.CacheHits, summary.Claims = cached.stats()
	summary.InputTokens, summary.Seconds = tokens(), time.Since(started).Seconds()
	summary.JunkRules = ledger.Report(3, 0.5)
	if err := writeJSON(filepath.Join(out, "ledger.json"), ledger.Report(1, 0)); err != nil {
		return err
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
	return nil
}

func evaluatePage(ctx context.Context, engine *fingers.Engine, j *judge.Judge, path string) (r record, err error) {
	r.ID = filepath.Base(path)
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("panic: %v", p)
		}
		if err != nil {
			r.Err = err.Error()
		}
	}()
	raw, err := os.ReadFile(path)
	if err != nil {
		return r, err
	}
	r.SHA256 = digest(raw)
	started := time.Now()
	r.Baseline, err = engine.DetectContent(raw)
	r.RuleMs = ms(time.Since(started))
	if err != nil {
		return r, err
	}
	err = judgeRecord(ctx, j, raw, &r)
	return r, err
}

// loadLabels converts the old keep/drop/version input once at the boundary.
// All scoring thereafter uses productLabel and exact names or explicit aliases.
func loadLabels(path string) (map[string][]productLabel, error) {
	out := map[string][]productLabel{}
	if path == "" {
		return out, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var values map[string]json.RawMessage
	if err := json.Unmarshal(data, &values); err != nil {
		return nil, err
	}
	for id, raw := range values {
		if strings.HasPrefix(strings.TrimSpace(string(raw)), "[") {
			var labels []productLabel
			if err := json.Unmarshal(raw, &labels); err != nil {
				return nil, err
			}
			out[id] = labels
			continue
		}
		var old struct {
			Keep    []string
			Drop    []string
			Version *struct{ Product, Value string }
		}
		if err := json.Unmarshal(raw, &old); err != nil {
			return nil, err
		}
		for _, name := range old.Keep {
			out[id] = append(out[id], productLabel{Product: name, Present: true})
		}
		for _, name := range old.Drop {
			out[id] = append(out[id], productLabel{Product: name})
		}
		if old.Version != nil {
			found := false
			for i := range out[id] {
				if judge.NormalizeName(out[id][i].Product) == judge.NormalizeName(old.Version.Product) {
					out[id][i].Version = &old.Version.Value
					found = true
					break
				}
			}
			if !found {
				out[id] = append(out[id], productLabel{Product: old.Version.Product, Present: true, Version: &old.Version.Value})
			}
		}
	}
	return out, nil
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

type limited struct{ tick <-chan time.Time }

func (l *limited) RoundTrip(req *http.Request) (*http.Response, error) {
	select {
	case <-l.tick:
	case <-req.Context().Done():
		return nil, req.Context().Err()
	}
	return http.DefaultTransport.RoundTrip(req)
}

var minConfidence float64

func newJudge(p jev.Provider) *judge.Judge {
	j := judge.New(p)
	if minConfidence != 0 {
		j.MinConfidence = minConfidence
	}
	return j
}
