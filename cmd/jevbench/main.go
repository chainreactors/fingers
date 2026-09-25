// jevbench measures the Jev judgement layer, exactly as SDK callers run it
// (fingers.Engine.Refine), on a directory of raw HTTP responses.
//
//	TYPESAFE_API_KEY=... jevbench -samples testdata/samples -labels testdata/labels.json
//	TYPESAFE_API_KEY=... jevbench -samples cclogin/samples -cache cache -out report
//
// Jev answers are cached on disk by request content, so reruns are free and
// an interrupted run resumes. Build with -tags goregexp.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/chainreactors/fingers"
	"github.com/chainreactors/fingers/common"
	"github.com/chainreactors/fingers/jev"
	"github.com/chainreactors/logs"
)

// row is the outcome for one page, written to rows.jsonl for review.
type row struct {
	ID         string            `json:"id"`
	Rules      []string          `json:"rules"` // name@engine of every rule hit
	Accepted   []string          `json:"accepted"`
	Rejected   []string          `json:"rejected,omitempty"`
	Recall     []string          `json:"recall,omitempty"`
	Layers     map[string]string `json:"layers,omitempty"`
	Primary    string            `json:"primary,omitempty"`
	Version    string            `json:"version,omitempty"`
	JevVersion bool              `json:"jev_version,omitempty"` // Version written by Jev, not by a rule
	Kind       string            `json:"kind"`
	Generic    bool              `json:"generic"`
	NewFinger  bool              `json:"new_fingerprint_candidate,omitempty"`
	Err        string            `json:"error,omitempty"`

	// rules vs rules+Jev on the same page
	RuleProducts int      `json:"rule_products"`       // rule hits after folding spellings
	TextOnly     []string `json:"text_only,omitempty"` // rule hits named only in visible text: likely false positives
	TextOnlyKept int      `json:"text_only_kept"`      // of those, accepted by Jev
	Generator    string   `json:"generator,omitempty"` // "wordpress 6.4.2": the reference version
	RuleGenVer   string   `json:"rule_gen_version,omitempty"`
	JevGenVer    string   `json:"jev_gen_version,omitempty"`
	RuleMs       float64  `json:"rule_ms"`
	JevMs        float64  `json:"jev_ms"`

	frames      common.Frameworks   // annotated
	ruleEngines map[string][]string // rule name -> engines
	err         error
}

func main() {
	samples := flag.String("samples", "testdata/samples", "directory of raw HTTP responses (*.http)")
	labels := flag.String("labels", "", "optional ground truth (see testdata/labels.json)")
	cache := flag.String("cache", "jevcache", "directory caching Jev answers")
	out := flag.String("out", "jevreport", "output directory")
	rps := flag.Float64("rps", 15, "max Jev requests per second")
	workers := flag.Int("workers", 16, "concurrent pages")
	limit := flag.Int("limit", 0, "only the first N samples (0 = all)")
	endpoint := flag.String("endpoint", jev.DefaultEndpoint, "Jev API endpoint")
	flag.Parse()
	logs.Log.SetLevel(logs.ErrorLevel)
	if err := run(*samples, *labels, *cache, *out, *endpoint, *rps, *workers, *limit); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(samples, labelsPath, cacheDir, out, endpoint string, rps float64, workers, limit int) error {
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
	client, err := jev.NewClient("")
	if err != nil {
		return err
	}
	client.Endpoint = endpoint
	sim := newSimCheck(cacheDir)
	client.Cache = sim
	client.HTTP.Transport = &limited{tick: time.NewTicker(time.Duration(float64(time.Second) / rps)).C}

	engine, err := fingers.NewEngine(fingers.FingersEngine, fingers.FingerPrintEngine, fingers.EHoleEngine, fingers.GobyEngine, fingers.WappalyzerEngine)
	if err != nil {
		return err
	}
	engine.AttachJev(client)

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
				rows[i] = judge(ctx, engine, files[i])
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
	report(&b, rows, client, time.Since(start))
	fmt.Fprintf(&b, "\n## 相似度缓存（SimilarDistance=%d，模拟）\n\n", jev.SimilarDistance)
	fmt.Fprintf(&b, "- 请求 %d 次，其中 %d 次（%.1f%%）可以直接复用相似页面的答案；复用答案与真实答案在所有决策上完全一致的占 %d/%d（%.1f%%）\n",
		sim.requests, sim.hits, 100*div(sim.hits, sim.requests), sim.agree, sim.hits, 100*div(sim.agree, sim.hits))
	for _, k := range sortedKeys(sim.diffs, func(k string) int { return sim.diffs[k] }) {
		fmt.Fprintf(&b, "  - 不一致的题目 %s: %d\n", k, sim.diffs[k])
	}
	if labelsPath != "" {
		if err := evaluate(&b, rows, labelsPath); err != nil {
			return err
		}
	}
	fmt.Print(b.String())
	return os.WriteFile(filepath.Join(out, "report.md"), []byte(b.String()), 0o644)
}

func judge(ctx context.Context, engine *fingers.Engine, path string) (r *row) {
	r = &row{ID: filepath.Base(path), ruleEngines: map[string][]string{}}
	defer func() {
		if p := recover(); p != nil { // one malformed page must not stop a long run
			r.Err = fmt.Sprintf("panic: %v", p)
		}
	}()
	raw, err := os.ReadFile(path)
	var page *jev.Page
	if err == nil {
		page, err = jev.NewPage(raw) // for code-only evidence; Refine builds its own
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
		keys[jev.NormalizeName(f.Name)] = true
		if ev := page.Evidence(f.Name); len(ev) == 1 && ev[0] == "text" {
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
	page, err = engine.Refine(ctx, raw, r.frames)
	r.JevMs = ms(time.Since(t))
	if err != nil {
		r.Err, r.err = err.Error(), err
		return r
	}
	r.JevGenVer = versionOf(jev.Accepted(r.frames), product)
	for _, name := range r.TextOnly {
		if f := r.frames[name]; f != nil && !f.HasTag(jev.TagRejected) {
			r.TextOnlyKept++
		}
	}
	r.Kind, r.Generic, r.Layers = page.Kind, page.Generic, map[string]string{}
	identified := false // an accepted application or device: the page's product is known
	for _, f := range r.frames {
		for _, t := range f.Tags {
			if strings.HasPrefix(t, jev.TagLayer) {
				r.Layers[f.Name] = strings.TrimPrefix(t, jev.TagLayer)
			}
		}
		switch {
		case f.HasTag(jev.TagRejected):
			r.Rejected = append(r.Rejected, f.Name)
		case f.HasTag(jev.TagDup):
		default:
			r.Accepted = append(r.Accepted, f.Name)
			switch jev.Layer(r.Layers[f.Name]) {
			case jev.LayerApplication, jev.LayerDevice:
				identified = true
			}
		}
		if f.HasTag(jev.TagRecall) {
			r.Recall = append(r.Recall, f.Name)
		}
	}
	if p := jev.Primary(r.frames); p != nil {
		r.Primary, r.Version = p.Name, p.Version
		r.JevVersion = p.Version != "" && p.Version != versions[p.Name]
	}
	// A stock page nobody identified is material for a new rule; a server's
	// own default, error or index page is identified by the server.
	serverPage := r.Kind == "default_install" || r.Kind == "error_page" || r.Kind == "directory_listing"
	r.NewFinger = r.Generic && r.Primary == "" && !identified && !serverPage
	sort.Strings(r.Accepted)
	sort.Strings(r.Rejected)
	return r
}

func report(b *strings.Builder, rows []*row, c *jev.Client, took time.Duration) {
	w := func(format string, a ...interface{}) { fmt.Fprintf(b, format+"\n", a...) }
	var pages, errs, rules, accepted, recall, primary, generic, newFinger int
	var ruleProducts, textOnly, textOnlyKept, rejected, genPages int
	var genRule, genJev [3]int // correct, wrong, missing
	var perRule, perJev []int
	var ruleMs, jevMs []float64
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
		perJev = append(perJev, len(r.Accepted))
		ruleMs = append(ruleMs, r.RuleMs)
		jevMs = append(jevMs, r.JevMs)
		kinds[r.Kind]++
		if r.Primary != "" {
			primary++
		}
		if r.Generator != "" {
			genPages++
			want := r.Generator[strings.LastIndex(r.Generator, " ")+1:]
			grade(&genRule, r.RuleGenVer, want)
			grade(&genJev, r.JevGenVer, want)
		}
		if r.Generic {
			generic++
		}
		if r.NewFinger {
			newFinger++
			newFingers = append(newFingers, r.ID)
		}
		for _, f := range r.frames {
			rejected := f.HasTag(jev.TagRejected)
			for _, e := range r.ruleEngines[f.Name] {
				add(byEngine, e, rejected)
				add(byRule, e+"/"+f.Name, rejected)
			}
		}
	}
	w("# 纯规则 vs 规则 + Jev\n")
	w("pages %d, errors %d, took %s\n", pages, errs, took.Round(time.Second))
	w("| 指标 | 纯规则 | 规则 + Jev |\n|---|---|---|")
	w("| 每页结果条数 mean / p90 | %.2f / %d | %.2f / %d |", mean(perRule), p90(perRule), mean(perJev), p90(perJev))
	w("| 每页不同产品数（按名字归并） | %.2f | %.2f |", div(ruleProducts, pages), div(accepted, pages))
	w("| 同名重复条目 | %d | 0（标 jev:dup） |", rules-ruleProducts)
	w("| 仅正文出现的命中（疑似误报） | %d | %d |", textOnly, textOnlyKept)
	w("| 被否决的规则命中 | — | %d / %d（%.1f%%） |", rejected, rules, 100*div(rejected, rules))
	w("| 召回（规则漏掉、Jev 确认） | 0 | %d |", recall)
	w("| 主应用 | — | %d 页 |", primary)
	w("| 版本号 vs generator：正确 / 错误 / 缺失（%d 页） | %d / %d / %d | %d / %d / %d |", genPages,
		genRule[0], genRule[1], genRule[2], genJev[0], genJev[1], genJev[2])
	w("| 页面类型 / 是否通用页面 | — | ✓ / 通用 %d 页 |", generic)
	w("| 新指纹候选 | — | %d |", newFinger)
	w("| 每页耗时 p50 / p95 | %.1fms / %.1fms | +%.0fms / +%.0fms |", pct(ruleMs, 50), pct(ruleMs, 95), pct(jevMs, 50), pct(jevMs, 95))
	w("| 成本 | 0 | %d 次请求（缓存命中 %d），%d input tokens，≈ $%.3f，折合每万页 $%.2f |",
		c.Requests, c.CacheHits, c.InputTokens, float64(c.InputTokens)*0.042/1e6, float64(c.InputTokens)*0.042/1e6/float64(max(pages, 1))*1e4)
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
		if r.Kind == l.PageKind {
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
	want := jev.NormalizeName(name)
	var found *common.Framework
	for _, f := range jev.Accepted(frames) {
		got := jev.NormalizeName(f.Name)
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
		key := jev.NormalizeName(f.Name)
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

func sortedKeys[V any](m map[string]V, weight func(string) int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(a, b int) bool {
		if wa, wb := weight(keys[a]), weight(keys[b]); wa != wb {
			return wa > wb
		}
		return keys[a] < keys[b]
	})
	return keys
}

// fileCache is an exact jev.Cache on disk, one file per request.
type fileCache string

func (d fileCache) path(key string, sig uint64) string {
	return filepath.Join(string(d), fmt.Sprintf("%s_%016x.json", key, sig))
}

func (d fileCache) Get(key string, sig uint64) ([]byte, bool) {
	data, err := os.ReadFile(d.path(key, sig))
	return data, err == nil
}

func (d fileCache) Put(key string, sig uint64, value []byte) {
	path := d.path(key, sig)
	if os.WriteFile(path+".tmp", value, 0o644) == nil {
		os.Rename(path+".tmp", path)
	}
}

// simCheck measures the similarity cache without trusting it: every page is
// still answered exactly, and whenever an earlier similar page would have
// been served instead, the two answers are compared decision by decision.
type simCheck struct {
	fileCache
	mu                    sync.Mutex
	seen                  map[string][]simEntry // key -> earlier answers
	pending               map[string][]byte     // key+sig -> answer a similarity cache would have served
	requests, hits, agree int
	diffs                 map[string]int // question key prefix -> disagreements
}

type simEntry struct {
	sig   uint64
	value []byte
}

func newSimCheck(dir string) *simCheck {
	return &simCheck{fileCache: fileCache(dir), seen: map[string][]simEntry{}, pending: map[string][]byte{}, diffs: map[string]int{}}
}

func (c *simCheck) Get(key string, sig uint64) ([]byte, bool) {
	value, ok := c.fileCache.Get(key, sig)
	c.mu.Lock()
	defer c.mu.Unlock()
	var near []byte
	for _, e := range c.seen[key] {
		if e.sig != sig && jev.Similar(e.sig, sig) {
			near = e.value
			break
		}
	}
	if ok {
		c.observe(key, sig, near, value)
	} else if near != nil {
		c.pending[fmt.Sprintf("%s_%x", key, sig)] = near
	}
	return value, ok
}

func (c *simCheck) Put(key string, sig uint64, value []byte) {
	c.fileCache.Put(key, sig, value)
	c.mu.Lock()
	defer c.mu.Unlock()
	id := fmt.Sprintf("%s_%x", key, sig)
	c.observe(key, sig, c.pending[id], value)
	delete(c.pending, id)
}

func (c *simCheck) observe(key string, sig uint64, near, value []byte) {
	c.requests++
	c.seen[key] = append(c.seen[key], simEntry{sig, value})
	if near == nil {
		return
	}
	c.hits++
	var a, b jev.Response
	json.Unmarshal(near, &a)
	json.Unmarshal(value, &b)
	same := true
	for k, x := range b.Answers {
		y := a.Answers[k]
		if x.Choice != y.Choice || (x.Noul >= jev.Threshold) != (y.Noul >= jev.Threshold) {
			same = false
			c.diffs[strings.TrimRight(k, "0123456789")]++
		}
	}
	if same {
		c.agree++
	}
}

// limited rate-limits Jev requests; cache hits never reach it.
type limited struct{ tick <-chan time.Time }

func (l *limited) RoundTrip(req *http.Request) (*http.Response, error) {
	select {
	case <-l.tick:
	case <-req.Context().Done():
		return nil, req.Context().Err()
	}
	return http.DefaultTransport.RoundTrip(req)
}
