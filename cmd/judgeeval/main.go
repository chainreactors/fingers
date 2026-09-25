// judgeeval compares the rule engines alone with rules plus a judge provider,
// exactly as SDK callers run it (judge.Judge.Refine), on a directory of
// raw HTTP responses; it is also how a new provider is calibrated.
//
//	TYPESAFE_API_KEY=... judgeeval -provider jev -samples testdata/samples -labels testdata/labels.json
//	TYPESAFE_API_KEY=... judgeeval -provider jev -samples cc/samples -cache cache -out report
//
// Answers are cached on disk, so reruns are free and an interrupted run
// resumes. Build with -tags goregexp.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math"
	"math/bits"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/chainreactors/fingers"
	"github.com/chainreactors/fingers/common"
	"github.com/chainreactors/fingers/judge"
	"github.com/chainreactors/fingers/judge/jev"
	"github.com/chainreactors/logs"
)

// row is the outcome for one page, written to rows.jsonl for review.
type row struct {
	ID           string            `json:"id"`
	Rules        []string          `json:"rules"` // name@engine of every rule hit
	Accepted     []string          `json:"accepted"`
	Rejected     []string          `json:"rejected,omitempty"`
	Recall       []string          `json:"recall,omitempty"`
	Layers       map[string]string `json:"layers,omitempty"`
	Primary      string            `json:"primary,omitempty"`
	Version      string            `json:"version,omitempty"`
	JudgeVersion bool              `json:"judge_version,omitempty"` // Version written by the judge, not by a rule
	Kind         judge.Kind        `json:"kind"`
	Generic      bool              `json:"generic"`
	NewFinger    bool              `json:"new_fingerprint_candidate,omitempty"`
	Err          string            `json:"error,omitempty"`

	// rules vs rules+judge on the same page
	RuleProducts int      `json:"rule_products"`       // rule hits after folding spellings
	TextOnly     []string `json:"text_only,omitempty"` // rule hits named only in visible text: likely false positives
	TextOnlyKept int      `json:"text_only_kept"`      // of those, accepted by the judge
	Generator    string   `json:"generator,omitempty"` // "wordpress 6.4.2": the reference version
	RuleGenVer   string   `json:"rule_gen_version,omitempty"`
	JudgeGenVer  string   `json:"judge_gen_version,omitempty"`
	RuleMs       float64  `json:"rule_ms"`
	JudgeMs      float64  `json:"judge_ms"`

	frames      common.Frameworks   // annotated
	ruleEngines map[string][]string // rule name -> engines
	err         error
}

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
func newProvider(name, endpoint string, transport http.RoundTripper) (p judge.Provider, tokens func() int64, err error) {
	switch name {
	case "jev":
		jp, err := jev.New("")
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
	files, err := filepath.Glob(filepath.Join(samples, "*.http"))
	if err != nil {
		return err
	}
	sort.Strings(files)
	if limit > 0 && len(files) > limit {
		files = files[:limit]
	}
	for _, d := range []string{cacheDir, out} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	provider, tokens, err := newProvider(providerName, endpoint, &limited{tick: time.NewTicker(time.Duration(float64(time.Second) / rps)).C})
	if err != nil {
		return err
	}
	j := judge.New(provider)
	// Measure similarity rather than use it: every page gets its own answers.
	j.SimilarDistance = 0
	sim := newSimCheck(cacheDir)
	j.Cache = sim

	engine, err := fingers.NewEngine(fingers.FingersEngine, fingers.FingerPrintEngine, fingers.EHoleEngine, fingers.GobyEngine, fingers.WappalyzerEngine)
	if err != nil {
		return err
	}
	j.Known = judge.NewRetriever(engine.Names())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rows := make([]*row, len(files))
	jobs := make(chan int)
	var wg sync.WaitGroup
	var fatal error
	var once sync.Once
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				rows[i] = evaluatePage(ctx, engine, j, files[i])
				var apiErr *jev.APIError
				if rows[i].err != nil && errors.As(rows[i].err, &apiErr) && apiErr.Status == 401 {
					once.Do(func() { fatal = errors.New("unauthorized: check " + jev.EnvAPIKey); cancel() })
				}
			}
		}()
	}
	start := time.Now()
	for i := range files {
		if ctx.Err() != nil {
			break
		}
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	if fatal != nil {
		return fatal
	}

	f, err := os.Create(filepath.Join(out, "rows.jsonl"))
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)
	for _, r := range rows {
		if r != nil {
			enc.Encode(r)
		}
	}
	f.Close()

	var b strings.Builder
	report(&b, rows, provider.ID(), j, tokens(), time.Since(start))
	sim.report(&b, judge.DefaultSimilarDistance)
	if labelsPath != "" {
		if err := evaluate(&b, rows, labelsPath); err != nil {
			return err
		}
	}
	fmt.Print(b.String())
	return os.WriteFile(filepath.Join(out, "report.md"), []byte(b.String()), 0o644)
}

func evaluatePage(ctx context.Context, engine *fingers.Engine, j *judge.Judge, path string) (r *row) {
	r = &row{ID: filepath.Base(path), ruleEngines: map[string][]string{}}
	defer func() {
		if p := recover(); p != nil { // one malformed page must not stop a long run
			r.Err = fmt.Sprintf("panic: %v", p)
		}
	}()
	raw, err := os.ReadFile(path)
	var page *judge.Page
	if err == nil {
		page, err = judge.NewPage(raw) // for code-only evidence; Refine builds its own
	}
	if err == nil {
		t := time.Now()
		r.frames, err = engine.DetectContent(raw)
		r.RuleMs = ms(time.Since(t))
	}
	if err != nil {
		r.Err, r.err = err.Error(), err
		return r
	}
	product, want := generatorVersion(page.Generator)
	if want != "" {
		r.Generator = product + " " + want
	}
	keys := map[string]bool{}
	for _, f := range r.frames {
		keys[judge.NormalizeName(f.Name)] = true
		if textOnly(page, f.Name) {
			r.TextOnly = append(r.TextOnly, f.Name)
		}
	}
	r.RuleProducts = len(keys)
	r.RuleGenVer = versionOf(r.frames, product)
	versions := map[string]string{}
	for _, f := range r.frames {
		for from := range f.Froms {
			r.Rules = append(r.Rules, f.Name+"@"+from.String())
			r.ruleEngines[f.Name] = append(r.ruleEngines[f.Name], from.String())
		}
		versions[f.Name] = f.Version
	}
	sort.Strings(r.Rules)
	t := time.Now()
	accepted, err := j.Refine(ctx, raw, r.frames)
	r.JudgeMs = ms(time.Since(t))
	if err != nil {
		r.Err, r.err = err.Error(), err
		return r
	}
	inspected, err := j.Inspect(ctx, raw, r.frames)
	if err != nil {
		r.Err, r.err = err.Error(), err
		return r
	}
	kind, generic, err := j.Classify(ctx, raw)
	if err != nil {
		r.Err, r.err = err.Error(), err
		return r
	}
	for name, f := range accepted {
		if target := inspected[name]; target != nil {
			target.Attributes = f.Attributes
		}
	}
	r.frames = inspected
	r.JudgeGenVer = versionOf(accepted, product)
	for _, name := range r.TextOnly {
		if f := r.frames[name]; f != nil && (f.Judge == nil || !f.Judge.Rejected) {
			r.TextOnlyKept++
		}
	}
	r.Kind, r.Generic, r.Layers = kind, generic, map[string]string{}
	for _, f := range r.frames {
		v := f.Judge
		if v == nil {
			r.Accepted = append(r.Accepted, f.Name)
			continue
		}
		if v.Layer != "" {
			r.Layers[f.Name] = v.Layer
		}
		switch {
		case v.Rejected:
			r.Rejected = append(r.Rejected, f.Name)
		case v.Duplicate:
		default:
			r.Accepted = append(r.Accepted, f.Name)
		}
		if v.Recalled {
			r.Recall = append(r.Recall, f.Name)
		}
	}
	if p := r.frames.Primary(); p != nil {
		r.Primary, r.Version = p.Name, p.Version
		r.JudgeVersion = p.Version != "" && p.Version != versions[p.Name]
	}
	r.NewFinger, err = j.IsUnknownProduct(ctx, raw, accepted)
	if err != nil {
		r.Err, r.err = err.Error(), err
		return r
	}
	sort.Strings(r.Accepted)
	sort.Strings(r.Rejected)
	return r
}

// textOnly reports whether name occurs in the page's visible text and in no
// structural evidence: the code-only proxy for a false positive.
func textOnly(p *judge.Page, name string) bool {
	n := strings.ToLower(name)
	if len(n) < 3 || !strings.Contains(strings.ToLower(p.Text), n) {
		return false
	}
	var structural []string
	for k, v := range p.Headers {
		structural = append(structural, k+":"+v)
	}
	structural = append(structural, p.Title, p.Generator, p.Description)
	for _, list := range [][]string{p.Cookies, p.Scripts, p.Styles, p.InlineHints, p.Comments, p.Forms} {
		structural = append(structural, list...)
	}
	return !strings.Contains(strings.ToLower(strings.Join(structural, " ")), n)
}

func report(b *strings.Builder, rows []*row, providerID string, j *judge.Judge, tokens int64, took time.Duration) {
	w := func(format string, a ...interface{}) { fmt.Fprintf(b, format+"\n", a...) }
	var pages, errs, rules, accepted, recall, primary, generic, newFinger int
	var ruleProducts, textOnly, textOnlyKept, rejected, genPages int
	var genRule, genJudge [3]int // correct, wrong, missing
	var perRule, perJudge []int
	var ruleMs, judgeMs []float64
	kinds := map[string]int{}
	type stat struct{ hits, rejected int }
	byEngine, byRule := map[string]*stat{}, map[string]*stat{}
	add := func(m map[string]*stat, k string, rejected bool) {
		if m[k] == nil {
			m[k] = &stat{}
		}
		m[k].hits++
		if rejected {
			m[k].rejected++
		}
	}
	var newFingers []string
	for _, r := range rows {
		if r == nil || r.Err != "" {
			errs++
			continue
		}
		pages++
		rules += len(r.frames) - len(r.Recall)
		accepted += len(r.Accepted)
		recall += len(r.Recall)
		ruleProducts += r.RuleProducts
		textOnly += len(r.TextOnly)
		textOnlyKept += r.TextOnlyKept
		rejected += len(r.Rejected)
		perRule = append(perRule, len(r.frames)-len(r.Recall))
		perJudge = append(perJudge, len(r.Accepted))
		ruleMs = append(ruleMs, r.RuleMs)
		judgeMs = append(judgeMs, r.JudgeMs)
		kinds[string(r.Kind)]++
		if r.Primary != "" {
			primary++
		}
		if r.Generator != "" {
			genPages++
			want := r.Generator[strings.LastIndex(r.Generator, " ")+1:]
			grade(&genRule, r.RuleGenVer, want)
			grade(&genJudge, r.JudgeGenVer, want)
		}
		if r.Generic {
			generic++
		}
		if r.NewFinger {
			newFinger++
			newFingers = append(newFingers, r.ID)
		}
		for _, f := range r.frames {
			rejected := f.Judge != nil && f.Judge.Rejected
			for _, e := range r.ruleEngines[f.Name] {
				add(byEngine, e, rejected)
				add(byRule, e+"/"+f.Name, rejected)
			}
		}
	}
	w("# 纯规则 vs 规则 + judge（%s）\n", providerID)
	w("pages %d, errors %d, took %s\n", pages, errs, took.Round(time.Second))
	w("| 指标 | 纯规则 | 规则 + judge |\n|---|---|---|")
	w("| 每页结果条数 mean / p90 | %.2f / %d | %.2f / %d |", mean(perRule), p90(perRule), mean(perJudge), p90(perJudge))
	w("| 每页不同产品数（按名字归并） | %.2f | %.2f |", div(ruleProducts, pages), div(accepted, pages))
	w("| 同名重复条目 | %d | 0（标为 Duplicate） |", rules-ruleProducts)
	w("| 仅正文出现的命中（疑似误报） | %d | %d |", textOnly, textOnlyKept)
	w("| 被否决的规则命中 | — | %d / %d（%.1f%%） |", rejected, rules, 100*div(rejected, rules))
	w("| 召回（规则漏掉、judge 确认） | 0 | %d |", recall)
	w("| 主应用 | — | %d 页 |", primary)
	w("| 版本号 vs generator：正确 / 错误 / 缺失（%d 页） | %d / %d / %d | %d / %d / %d |", genPages,
		genRule[0], genRule[1], genRule[2], genJudge[0], genJudge[1], genJudge[2])
	w("| 页面类型 / 是否通用页面 | — | ✓ / 通用 %d 页 |", generic)
	w("| 新指纹候选 | — | %d |", newFinger)
	w("| 每页耗时 p50 / p95 | %.1fms / %.1fms | +%.0fms / +%.0fms |", pct(ruleMs, 50), pct(ruleMs, 95), pct(judgeMs, 50), pct(judgeMs, 95))
	w("| 成本 | 0 | %d 次请求（缓存直接答完 %d 轮），%d input tokens（jev 按 $0.042/Mtok ≈ $%.3f，折合每万页 $%.2f） |",
		j.Requests, j.CacheHits, tokens, float64(tokens)*0.042/1e6, float64(tokens)*0.042/1e6/math.Max(float64(pages), 1)*1e4)
	w("\n## page kind\n")
	for _, k := range sortedKeys(kinds, func(k string) int { return kinds[k] }) {
		w("- %s: %d", k, kinds[k])
	}
	w("\n## rejections per engine\n\n| engine | hits | rejected | rate |\n|---|---|---|---|")
	for _, e := range sortedKeys(byEngine, func(k string) int { return byEngine[k].hits }) {
		s := byEngine[e]
		w("| %s | %d | %d | %.1f%% |", e, s.hits, s.rejected, 100*div(s.rejected, s.hits))
	}
	w("\n## worst rules (>= 5 hits): candidates to fix\n\n| rule | hits | rejected |\n|---|---|---|")
	worst := sortedKeys(byRule, func(k string) int { return byRule[k].rejected*1000 + byRule[k].hits })
	for i, k := range worst {
		if s := byRule[k]; i < 25 && s.hits >= 5 && s.rejected*2 > s.hits {
			w("| %s | %d | %d |", k, s.hits, s.rejected)
		}
	}
	if len(newFingers) > 0 {
		w("\n## new fingerprint candidates\n")
		for _, id := range newFingers {
			w("- %s", id)
		}
	}
}

// label is the ground truth for one sample: Keep are real products, Drop are
// false positives the rules report.
type label struct {
	PageKind string   `json:"page_kind"`
	Generic  bool     `json:"generic"`
	Keep     []string `json:"keep"`
	Drop     []string `json:"drop"`
	Version  *struct {
		Product string `json:"product"`
		Value   string `json:"value"` // "" = the page does not show it
	} `json:"version"`
}

func evaluate(b *strings.Builder, rows []*row, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var labels map[string]label
	if err := json.Unmarshal(data, &labels); err != nil {
		return err
	}
	w := func(format string, a ...interface{}) { fmt.Fprintf(b, format+"\n", a...) }
	var kept, keep, dropped, drop, kind, generic, pages, version, versions int
	var misses []string
	for _, r := range rows {
		l, ok := labels[r.ID]
		if !ok || r.Err != "" {
			continue
		}
		pages++
		for _, name := range l.Keep {
			keep++
			if find(r.frames, name, false) != nil {
				kept++
			} else {
				misses = append(misses, r.ID+": lost "+name)
			}
		}
		for _, name := range l.Drop {
			drop++
			if find(r.frames, name, true) == nil {
				dropped++
			} else {
				misses = append(misses, r.ID+": kept "+name)
			}
		}
		if string(r.Kind) == l.PageKind {
			kind++
		}
		if r.Generic == l.Generic {
			generic++
		}
		if l.Version != nil {
			versions++
			got := ""
			if f := find(r.frames, l.Version.Product, false); f != nil {
				got = f.Version
			}
			if got == l.Version.Value {
				version++
			} else {
				misses = append(misses, fmt.Sprintf("%s: version of %s %q, want %q", r.ID, l.Version.Product, got, l.Version.Value))
			}
		}
	}
	w("\n## against labels (%d pages)\n", pages)
	w("- false positives removed %d/%d, real products kept %d/%d", dropped, drop, kept, keep)
	w("- page kind %d/%d, generic %d/%d, version %d/%d", kind, pages, generic, pages, version, versions)
	if len(misses) > 0 {
		w("\n### misses\n")
		for _, m := range misses {
			w("- %s", m)
		}
	}
	return nil
}

// find returns the accepted framework matching a label name, preferring one
// with a version. Label names are loose ("tomcat" for "apache-tomcat"), so a
// match is containment either way; strict (for false positive labels such as
// "tomcat_jk_connector") only lets the framework name contain the label.
func find(frames common.Frameworks, name string, strict bool) *common.Framework {
	want := judge.NormalizeName(name)
	var found *common.Framework
	for _, f := range frames.Accepted() {
		got := judge.NormalizeName(f.Name)
		if got == "" || !(strings.Contains(got, want) || !strict && strings.Contains(want, got)) {
			continue
		}
		if found == nil || found.Version == "" {
			found = f
		}
	}
	return found
}

var reVersion = regexp.MustCompile(`\d+(?:\.\d+)+`)

// generatorVersion reads the reference answer from a generator meta such as
// "WordPress 6.4.2": the product's first word and the version.
func generatorVersion(gen string) (string, string) {
	v := reVersion.FindString(gen)
	words := strings.FieldsFunc(strings.ToLower(gen), func(r rune) bool { return !unicode.IsLetter(r) })
	if v == "" || len(words) == 0 {
		return "", ""
	}
	return words[0], v
}

// versionOf is the version reported for product, preferring an exact name.
func versionOf(frames common.Frameworks, product string) string {
	if product == "" {
		return ""
	}
	var got string
	for _, f := range frames {
		key := judge.NormalizeName(f.Name)
		if f.Version == "" || !strings.HasPrefix(key, product) {
			continue
		}
		if key == product || got == "" {
			got = f.Version
		}
	}
	return got
}

func grade(g *[3]int, got, want string) {
	switch {
	case got == want:
		g[0]++
	case got != "":
		g[1]++
	default:
		g[2]++
	}
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

func mean(xs []int) float64 {
	sum := 0
	for _, x := range xs {
		sum += x
	}
	return div(sum, len(xs))
}

func p90(xs []int) int {
	if len(xs) == 0 {
		return 0
	}
	s := append([]int(nil), xs...)
	sort.Ints(s)
	return s[len(s)*9/10]
}

func pct(xs []float64, p int) float64 {
	if len(xs) == 0 {
		return 0
	}
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	return s[len(s)*p/100]
}

func div(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b)
}

// sortedKeys returns the keys of m, a map with string keys, by descending weight.
func sortedKeys(m interface{}, weight func(string) int) []string {
	var keys []string
	for _, k := range reflect.ValueOf(m).MapKeys() {
		keys = append(keys, k.String())
	}
	sort.Slice(keys, func(a, b int) bool {
		if wa, wb := weight(keys[a]), weight(keys[b]); wa != wb {
			return wa > wb
		}
		return keys[a] < keys[b]
	})
	return keys
}

// fileCache is an exact judge.Cache on disk, one file per answer: the
// signature is part of the file name, so distance is ignored.
type fileCache string

func (d fileCache) path(key string, sig uint64) string {
	return filepath.Join(string(d), fmt.Sprintf("%s_%016x.json", key, sig))
}

func (d fileCache) Get(key string, sig uint64, _ int) ([]byte, bool) {
	data, err := os.ReadFile(d.path(key, sig))
	return data, err == nil
}

func (d fileCache) Put(key string, sig uint64, value []byte) {
	path := d.path(key, sig)
	if os.WriteFile(path+".tmp", value, 0o644) == nil {
		os.Rename(path+".tmp", path)
	}
}

// simCheck measures the similarity cache without trusting it: every question
// is still answered for its exact page (by the file cache), and whenever an
// earlier page with the same key had a signature within maxProbe bits, its
// answer is compared with the real one, bucketed by distance. That shows
// which SimilarDistance is safe.
type simCheck struct {
	fileCache
	mu      sync.Mutex
	seen    map[string][]simEntry // key -> earlier answers
	pending map[string]simNear    // key+sig -> nearest earlier answer, until the real one arrives
	answers int
	byDist  [maxProbe + 1]struct{ reusable, agree int }
}

const maxProbe = 10

type simEntry struct {
	sig   uint64
	value []byte
}

type simNear struct {
	dist  int
	value []byte
}

func newSimCheck(dir string) *simCheck {
	return &simCheck{fileCache: fileCache(dir), seen: map[string][]simEntry{}, pending: map[string]simNear{}}
}

func (c *simCheck) nearest(key string, sig uint64) (simNear, bool) {
	best, ok := simNear{dist: maxProbe + 1}, false
	for _, e := range c.seen[key] {
		if d := bits.OnesCount64(e.sig ^ sig); d < best.dist {
			best, ok = simNear{d, e.value}, true
		}
	}
	return best, ok
}

func (c *simCheck) Get(key string, sig uint64, distance int) ([]byte, bool) {
	value, ok := c.fileCache.Get(key, sig, distance)
	c.mu.Lock()
	defer c.mu.Unlock()
	near, found := c.nearest(key, sig)
	if ok {
		c.observe(key, sig, near, found, value)
	} else if found {
		c.pending[fmt.Sprintf("%s_%x", key, sig)] = near
	}
	return value, ok
}

func (c *simCheck) Put(key string, sig uint64, value []byte) {
	c.fileCache.Put(key, sig, value)
	c.mu.Lock()
	defer c.mu.Unlock()
	id := fmt.Sprintf("%s_%x", key, sig)
	near, found := c.pending[id]
	delete(c.pending, id)
	c.observe(key, sig, near, found, value)
}

func (c *simCheck) observe(key string, sig uint64, near simNear, found bool, value []byte) {
	c.answers++
	c.seen[key] = append(c.seen[key], simEntry{sig, value})
	if !found || near.dist > maxProbe {
		return
	}
	var x, y judge.Answer
	json.Unmarshal(near.value, &x)
	json.Unmarshal(value, &y)
	c.byDist[near.dist].reusable++
	if x.Choice == y.Choice && (x.Yes >= 0.5) == (y.Yes >= 0.5) {
		c.byDist[near.dist].agree++
	}
}

func (c *simCheck) report(b *strings.Builder, current int) {
	fmt.Fprintf(b, "\n## 相似度缓存（模拟，当前默认 SimilarDistance=%d）\n\n", current)
	fmt.Fprintf(b, "共 %d 个答案。下表：若 SimilarDistance 取 d，能由相似页面（同标题）复用的答案数，以及其中与真实答案一致的比例。\n\n", c.answers)
	fmt.Fprintf(b, "| d | 可复用 | 一致 | 一致率 |\n|---|---|---|---|\n")
	reusable, agree := 0, 0
	for d := 0; d <= maxProbe; d++ {
		reusable += c.byDist[d].reusable
		agree += c.byDist[d].agree
		fmt.Fprintf(b, "| %d | %d | %d | %.1f%% |\n", d, reusable, agree, 100*div(agree, reusable))
	}
}

// limited rate-limits provider requests; cache hits never reach it.
type limited struct{ tick <-chan time.Time }

func (l *limited) RoundTrip(req *http.Request) (*http.Response, error) {
	select {
	case <-l.tick:
	case <-req.Context().Done():
		return nil, req.Context().Err()
	}
	return http.DefaultTransport.RoundTrip(req)
}
