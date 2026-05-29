package fingers

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/chainreactors/utils/ahocorasick"
	re2 "github.com/wasilibs/go-re2"
)

// ──────────────────────────────────────────────────────────────
// 1. Pattern Statistics — understand what we're optimizing
// ──────────────────────────────────────────────────────────────

func TestFingerPatternStatistics(t *testing.T) {
	engine := newPerfEngine(t)

	var totalBody, totalHeader, totalRegexp, totalVuln, totalVersion, totalMD5, totalMMH3, totalCert int
	var totalFingers, totalRules int
	var fingersWithBody, fingersWithHeader, fingersWithRegexp int

	for _, finger := range engine.HTTPFingers {
		totalFingers++
		hasBody, hasHeader, hasRegexp := false, false, false
		for _, rule := range finger.Rules {
			totalRules++
			if rule.Regexps == nil {
				continue
			}
			totalBody += len(rule.Regexps.Body)
			totalHeader += len(rule.Regexps.Header)
			totalRegexp += len(rule.Regexps.Regexp)
			totalVuln += len(rule.Regexps.Vuln)
			totalVersion += len(rule.Regexps.Version)
			totalMD5 += len(rule.Regexps.MD5)
			totalMMH3 += len(rule.Regexps.MMH3)
			totalCert += len(rule.Regexps.Cert)

			if len(rule.Regexps.Body) > 0 {
				hasBody = true
			}
			if len(rule.Regexps.Header) > 0 {
				hasHeader = true
			}
			if len(rule.Regexps.Regexp) > 0 || len(rule.Regexps.Vuln) > 0 {
				hasRegexp = true
			}
		}
		if hasBody {
			fingersWithBody++
		}
		if hasHeader {
			fingersWithHeader++
		}
		if hasRegexp {
			fingersWithRegexp++
		}
	}

	t.Logf("=== HTTP Fingerprint Pattern Statistics ===")
	t.Logf("Total HTTP fingers:    %d", totalFingers)
	t.Logf("Total rules:           %d", totalRules)
	t.Logf("")
	t.Logf("Body keywords:         %d  (fingers with body: %d)", totalBody, fingersWithBody)
	t.Logf("Header keywords:       %d  (fingers with header: %d)", totalHeader, fingersWithHeader)
	t.Logf("Regexp patterns:       %d  (fingers with regexp: %d)", totalRegexp, fingersWithRegexp)
	t.Logf("Vuln regexp patterns:  %d", totalVuln)
	t.Logf("Version patterns:      %d", totalVersion)
	t.Logf("MD5 hashes:            %d", totalMD5)
	t.Logf("MMH3 hashes:           %d", totalMMH3)
	t.Logf("Cert patterns:         %d", totalCert)
	t.Logf("")
	t.Logf("AC candidate keywords (body+header): %d", totalBody+totalHeader)
	t.Logf("RE2 candidate patterns (regexp+vuln+version): %d", totalRegexp+totalVuln+totalVersion)
}

// ──────────────────────────────────────────────────────────────
// 2. Real website data collection & helpers
// ──────────────────────────────────────────────────────────────

type realSiteData struct {
	Name    string
	Content []byte
}

func fetchRealSite(url string) ([]byte, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "%s %s\r\n", resp.Proto, resp.Status)
	for key, values := range resp.Header {
		for _, v := range values {
			fmt.Fprintf(&buf, "%s: %s\r\n", key, v)
		}
	}
	buf.WriteString("\r\n")
	io.Copy(&buf, resp.Body)
	return buf.Bytes(), nil
}

var testSites = []struct {
	Name string
	URL  string
}{
	{"nginx-default", "http://nginx.org"},
	{"apache-httpd", "http://httpd.apache.org"},
	{"github", "https://github.com"},
	{"cloudflare", "https://www.cloudflare.com"},
	{"wordpress", "https://wordpress.org"},
	{"jenkins", "https://www.jenkins.io"},
	{"grafana", "https://grafana.com"},
	{"elastic", "https://www.elastic.co"},
}

func loadTestSites(t *testing.T) []realSiteData {
	t.Helper()
	cacheFile := "/tmp/fingers_bench_sites.json.gz"

	if data, err := os.ReadFile(cacheFile); err == nil {
		gr, err := gzip.NewReader(bytes.NewReader(data))
		if err == nil {
			defer gr.Close()
			var sites []realSiteData
			if err := json.NewDecoder(gr).Decode(&sites); err == nil && len(sites) > 0 {
				t.Logf("loaded %d cached sites from %s", len(sites), cacheFile)
				return sites
			}
		}
	}

	var sites []realSiteData
	for _, s := range testSites {
		content, err := fetchRealSite(s.URL)
		if err != nil {
			t.Logf("SKIP %s: %v", s.Name, err)
			continue
		}
		sites = append(sites, realSiteData{Name: s.Name, Content: content})
		t.Logf("fetched %s: %d bytes", s.Name, len(content))
	}

	if len(sites) > 0 {
		var buf bytes.Buffer
		gw := gzip.NewWriter(&buf)
		json.NewEncoder(gw).Encode(sites)
		gw.Close()
		os.WriteFile(cacheFile, buf.Bytes(), 0644)
	}

	return sites
}

func generateSyntheticResponses() []realSiteData {
	return []realSiteData{
		{
			Name: "typical-nginx",
			Content: []byte("HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Type: text/html\r\nX-Powered-By: PHP/7.4.3\r\n\r\n<!DOCTYPE html><html><head><title>Welcome to nginx!</title></head><body><h1>Welcome to nginx!</h1><p>If you see this page, the nginx web server is successfully installed.</p></body></html>"),
		},
		{
			Name: "wordpress-site",
			Content: []byte("HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\nX-Powered-By: PHP/7.4.3\r\nLink: <https://example.com/wp-json/>; rel=\"https://api.w.org/\"\r\n\r\n<!DOCTYPE html><html lang=\"en-US\"><head><meta charset=\"UTF-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><link rel=\"stylesheet\" href=\"/wp-content/themes/flavor/style.css\"><script src=\"/wp-includes/js/jquery/jquery.min.js\"></script></head><body class=\"home blog wp-custom-logo\"><div id=\"page\"><header><h1 class=\"site-title\"><a href=\"/\">Example Blog</a></h1></header><main><article class=\"post\"><h2>Hello World</h2><p>Welcome to WordPress.</p></article></main><footer><p>Powered by WordPress</p></footer></div></body></html>"),
		},
		{
			Name: "spring-boot-app",
			Content: []byte("HTTP/1.1 200 OK\r\nServer: Apache-Coyote/1.1\r\nContent-Type: application/json\r\nX-Application-Context: application:8080\r\n\r\n{\"status\":\"UP\",\"components\":{\"db\":{\"status\":\"UP\",\"details\":{\"database\":\"MySQL\",\"validationQuery\":\"isValid()\"}},\"diskSpace\":{\"status\":\"UP\",\"details\":{\"total\":107374182400,\"free\":53687091200,\"threshold\":10485760,\"path\":\"/opt/app/.\",\"exists\":true}}},\"groups\":[\"liveness\",\"readiness\"]}"),
		},
		{
			Name: "tomcat-default",
			Content: []byte("HTTP/1.1 200 OK\r\nServer: Apache-Coyote/1.1\r\nContent-Type: text/html;charset=UTF-8\r\n\r\n<!DOCTYPE html><html lang=\"en\"><head><title>Apache Tomcat/9.0.50</title></head><body><h1>Apache Tomcat/9.0.50</h1><p>If you're seeing this, you've successfully installed Tomcat.</p><ul><li><a href=\"/manager/html\">Server Status</a></li><li><a href=\"/host-manager/html\">Host Manager</a></li></ul></body></html>"),
		},
		{
			Name: "iis-aspnet",
			Content: []byte("HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0\r\nX-Powered-By: ASP.NET\r\nX-AspNet-Version: 4.0.30319\r\n\r\n<!DOCTYPE html><html><head><title>IIS Windows Server</title></head><body><img src=\"iisstart.png\" alt=\"IIS\"><h1>Internet Information Services</h1></body></html>"),
		},
		{
			Name: "large-react-app",
			Content: generateLargeResponse(64 * 1024),
		},
		{
			Name: "very-large-response",
			Content: generateLargeResponse(256 * 1024),
		},
		{
			Name: "empty-body",
			Content: []byte("HTTP/1.1 302 Found\r\nServer: cloudflare\r\nLocation: /login\r\nCF-RAY: abc123\r\n\r\n"),
		},
	}
}

func generateLargeResponse(bodySize int) []byte {
	var buf bytes.Buffer
	buf.WriteString("HTTP/1.1 200 OK\r\nServer: nginx/1.21.0\r\nContent-Type: text/html\r\nX-Powered-By: Express\r\nSet-Cookie: session=abc123; Path=/; HttpOnly\r\n\r\n")
	buf.WriteString("<!DOCTYPE html><html><head><title>React App</title>")
	buf.WriteString("<script src=\"/static/js/main.chunk.js\"></script>")
	buf.WriteString("<link rel=\"stylesheet\" href=\"/static/css/main.chunk.css\">")
	buf.WriteString("</head><body><div id=\"root\">")

	filler := "<div class=\"component\"><span>Content block with various text including keywords that may partially match fingerprints like powered-by, server-info, and x-generator headers embedded in HTML.</span></div>\n"
	for buf.Len() < bodySize {
		buf.WriteString(filler)
	}
	buf.WriteString("</div></body></html>")
	return buf.Bytes()
}

// ──────────────────────────────────────────────────────────────
// 3. Aho-Corasick Optimization Prototype
// ──────────────────────────────────────────────────────────────

type acIndex struct {
	bodyAC         *ahocorasick.Automaton
	headerAC       *ahocorasick.Automaton
	bodyPatterns   []acPatternRef
	headerPatterns []acPatternRef
}

type acPatternRef struct {
	FingerIdx  int
	RuleIdx    int
	PatternIdx int
	Pattern    string
}

func buildACIndex(fingers Fingers) *acIndex {
	idx := &acIndex{}

	var bodyKeywords []string
	var headerKeywords []string

	for fi, finger := range fingers {
		for ri, rule := range finger.Rules {
			if rule.Regexps == nil {
				continue
			}
			for pi, body := range rule.Regexps.Body {
				bodyKeywords = append(bodyKeywords, body)
				idx.bodyPatterns = append(idx.bodyPatterns, acPatternRef{
					FingerIdx:  fi,
					RuleIdx:    ri,
					PatternIdx: pi,
					Pattern:    body,
				})
			}
			for pi, header := range rule.Regexps.Header {
				headerKeywords = append(headerKeywords, header)
				idx.headerPatterns = append(idx.headerPatterns, acPatternRef{
					FingerIdx:  fi,
					RuleIdx:    ri,
					PatternIdx: pi,
					Pattern:    header,
				})
			}
		}
	}

	if len(bodyKeywords) > 0 {
		ac, err := ahocorasick.NewBuilder().
			AddStrings(bodyKeywords).
			Build()
		if err == nil {
			idx.bodyAC = ac
		}
	}

	if len(headerKeywords) > 0 {
		ac, err := ahocorasick.NewBuilder().
			AddStrings(headerKeywords).
			Build()
		if err == nil {
			idx.headerAC = ac
		}
	}

	return idx
}

type acMatchResult struct {
	FingerIdx  int
	RuleIdx    int
	PatternIdx int
	MatchType  string
}

func (idx *acIndex) matchKeywords(header, body []byte) []acMatchResult {
	var results []acMatchResult

	if idx.headerAC != nil && len(header) > 0 {
		matches := idx.headerAC.FindAll(header, -1)
		for _, m := range matches {
			ref := idx.headerPatterns[m.PatternID]
			results = append(results, acMatchResult{
				FingerIdx:  ref.FingerIdx,
				RuleIdx:    ref.RuleIdx,
				PatternIdx: ref.PatternIdx,
				MatchType:  "header",
			})
		}
	}

	if idx.bodyAC != nil && len(body) > 0 {
		matches := idx.bodyAC.FindAll(body, -1)
		for _, m := range matches {
			ref := idx.bodyPatterns[m.PatternID]
			results = append(results, acMatchResult{
				FingerIdx:  ref.FingerIdx,
				RuleIdx:    ref.RuleIdx,
				PatternIdx: ref.PatternIdx,
				MatchType:  "body",
			})
		}
	}

	return results
}

// ──────────────────────────────────────────────────────────────
// 4. Baseline vs AC keyword matching benchmark
// ──────────────────────────────────────────────────────────────

func TestBaselineVsAC_Keywords(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping heavy performance comparison in short mode")
	}
	engine := newPerfEngine(t)

	sites := generateSyntheticResponses()
	realSites := loadTestSites(t)
	sites = append(sites, realSites...)

	if len(sites) == 0 {
		t.Fatal("no test data available")
	}

	acIdx := buildACIndex(engine.HTTPFingers)
	t.Logf("AC index built: %d body patterns, %d header patterns",
		len(acIdx.bodyPatterns), len(acIdx.headerPatterns))

	for _, site := range sites {
		content := NewContent(site.Content, "", true)

		// Baseline: current bytes.Contains approach
		runtime.GC()
		baseStart := time.Now()
		baselineHits := 0
		for _, finger := range engine.HTTPFingers {
			for _, rule := range finger.Rules {
				if rule.Regexps == nil {
					continue
				}
				for _, h := range rule.Regexps.Header {
					if content.Header != nil && bytes.Contains(content.Header, []byte(h)) {
						baselineHits++
					}
				}
				for _, b := range rule.Regexps.Body {
					body := content.Body
					if body == nil {
						body = content.Content
					}
					if bytes.Contains(body, []byte(b)) {
						baselineHits++
					}
				}
			}
		}
		baseElapsed := time.Since(baseStart)

		// AC approach
		runtime.GC()
		acStart := time.Now()
		acResults := acIdx.matchKeywords(content.Header, content.Body)
		acElapsed := time.Since(acStart)

		speedup := 0.0
		if acElapsed > 0 {
			speedup = float64(baseElapsed) / float64(acElapsed)
		}

		t.Logf("[%s] content=%dB baseline=%s(%d hits) AC=%s(%d hits) speedup=%.2fx",
			site.Name, len(site.Content), baseElapsed, baselineHits, acElapsed, len(acResults), speedup)
	}
}

// ──────────────────────────────────────────────────────────────
// 5. Baseline vs RE2 regex matching benchmark
// ──────────────────────────────────────────────────────────────

func TestBaselineVsRE2_Regex(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping heavy performance comparison in short mode")
	}
	engine := newPerfEngine(t)

	// Collect all compiled regexps from HTTP fingers
	type regInfo struct {
		Pattern  string
		Compiled CompiledRegexp
	}
	var allRegexps []regInfo
	for _, finger := range engine.HTTPFingers {
		for _, rule := range finger.Rules {
			if rule.Regexps == nil {
				continue
			}
			for _, r := range rule.Regexps.CompliedRegexp {
				allRegexps = append(allRegexps, regInfo{Pattern: r.String(), Compiled: r})
			}
			for _, r := range rule.Regexps.CompiledVulnRegexp {
				allRegexps = append(allRegexps, regInfo{Pattern: r.String(), Compiled: r})
			}
		}
	}
	t.Logf("Total regex patterns to test: %d", len(allRegexps))

	sites := generateSyntheticResponses()
	realSites := loadTestSites(t)
	sites = append(sites, realSites...)

	for _, site := range sites {
		content := NewContent(site.Content, "", true)

		// Go stdlib regexp (current approach)
		runtime.GC()
		goStart := time.Now()
		goHits := 0
		for _, ri := range allRegexps {
			if ri.Compiled.Match(content.Content) {
				goHits++
			}
		}
		goElapsed := time.Since(goStart)

		t.Logf("[%s] content=%dB go_regexp=%s(%d hits) patterns=%d",
			site.Name, len(site.Content), goElapsed, goHits, len(allRegexps))
	}
}

// ──────────────────────────────────────────────────────────────
// 6. Full engine match: Baseline vs AC-accelerated
// ──────────────────────────────────────────────────────────────

func TestFullEngineMatch_BaselineVsACPrefilter(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping heavy performance comparison in short mode")
	}
	engine := newPerfEngine(t)
	acIdx := buildACIndex(engine.HTTPFingers)

	sites := generateSyntheticResponses()
	realSites := loadTestSites(t)
	sites = append(sites, realSites...)

	const iterations = 100

	for _, site := range sites {
		// Baseline: full engine match
		runtime.GC()
		baseStart := time.Now()
		var baseFrames int
		for i := 0; i < iterations; i++ {
			fs, _ := engine.HTTPMatch(site.Content, "")
			baseFrames = len(fs)
		}
		baseElapsed := time.Since(baseStart)

		// AC prefilter: identify candidate fingers, then only run those
		content := NewContent(site.Content, "", true)
		runtime.GC()
		acStart := time.Now()
		var acFrames int
		for i := 0; i < iterations; i++ {
			acResults := acIdx.matchKeywords(content.Header, content.Body)

			candidateFingers := make(map[int]bool)
			for _, r := range acResults {
				candidateFingers[r.FingerIdx] = true
			}

			// Still need to run regex fingers that AC can't cover
			for fi, finger := range engine.HTTPFingers {
				if candidateFingers[fi] {
					continue
				}
				for _, rule := range finger.Rules {
					if rule.Regexps == nil {
						continue
					}
					if len(rule.Regexps.CompliedRegexp) > 0 || len(rule.Regexps.CompiledVulnRegexp) > 0 ||
						len(rule.Regexps.MD5) > 0 || len(rule.Regexps.MMH3) > 0 || len(rule.Regexps.Cert) > 0 {
						candidateFingers[fi] = true
						break
					}
				}
			}

			count := 0
			for fi := range candidateFingers {
				finger := engine.HTTPFingers[fi]
				_, _, ok := finger.PassiveMatch(content)
				if ok {
					count++
				}
			}
			acFrames = count
		}
		acElapsed := time.Since(acStart)

		speedup := 0.0
		if acElapsed > 0 {
			speedup = float64(baseElapsed) / float64(acElapsed)
		}

		t.Logf("[%s] %dx: baseline=%s(%d frameworks) AC_prefilter=%s(%d frameworks) speedup=%.2fx",
			site.Name, iterations, baseElapsed, baseFrames, acElapsed, acFrames, speedup)
	}
}

// ──────────────────────────────────────────────────────────────
// 7. Formal Benchmarks
// ──────────────────────────────────────────────────────────────

func BenchmarkKeywords_Baseline(b *testing.B) {
	engine := newPerfEngine(b)
	content := NewContent(generateLargeResponse(32*1024), "", true)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, finger := range engine.HTTPFingers {
			for _, rule := range finger.Rules {
				if rule.Regexps == nil {
					continue
				}
				for _, h := range rule.Regexps.Header {
					if content.Header != nil {
						bytes.Contains(content.Header, []byte(h))
					}
				}
				for _, bo := range rule.Regexps.Body {
					body := content.Body
					if body == nil {
						body = content.Content
					}
					bytes.Contains(body, []byte(bo))
				}
			}
		}
	}
}

func BenchmarkKeywords_AhoCorasick(b *testing.B) {
	engine := newPerfEngine(b)
	acIdx := buildACIndex(engine.HTTPFingers)
	content := NewContent(generateLargeResponse(32*1024), "", true)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		acIdx.matchKeywords(content.Header, content.Body)
	}
}

func BenchmarkRegexp_GoStdlib(b *testing.B) {
	engine := newPerfEngine(b)
	var allRegexps []CompiledRegexp
	for _, finger := range engine.HTTPFingers {
		for _, rule := range finger.Rules {
			if rule.Regexps == nil {
				continue
			}
			allRegexps = append(allRegexps, rule.Regexps.CompliedRegexp...)
			allRegexps = append(allRegexps, rule.Regexps.CompiledVulnRegexp...)
		}
	}

	content := NewContent(generateLargeResponse(32*1024), "", true)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, r := range allRegexps {
			r.Match(content.Content)
		}
	}
}

func BenchmarkFullMatch_NoAC(b *testing.B) {
	engine := newPerfEngine(b)
	content := NewContent(generateLargeResponse(32*1024), "", true)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.HTTPFingers.PassiveMatch(content, false)
	}
}

func BenchmarkFullMatch_WithAC(b *testing.B) {
	engine := newPerfEngine(b)
	content := generateLargeResponse(32 * 1024)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.HTTPMatch(content, "")
	}
}

func BenchmarkFullMatch_ACPrefilter(b *testing.B) {
	engine := newPerfEngine(b)
	acIdx := buildACIndex(engine.HTTPFingers)
	raw := generateLargeResponse(32 * 1024)
	content := NewContent(raw, "", true)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		acResults := acIdx.matchKeywords(content.Header, content.Body)
		candidateFingers := make(map[int]bool)
		for _, r := range acResults {
			candidateFingers[r.FingerIdx] = true
		}
		for fi, finger := range engine.HTTPFingers {
			if candidateFingers[fi] {
				continue
			}
			for _, rule := range finger.Rules {
				if rule.Regexps == nil {
					continue
				}
				if len(rule.Regexps.CompliedRegexp) > 0 || len(rule.Regexps.CompiledVulnRegexp) > 0 ||
					len(rule.Regexps.MD5) > 0 || len(rule.Regexps.MMH3) > 0 || len(rule.Regexps.Cert) > 0 {
					candidateFingers[fi] = true
					break
				}
			}
		}
		for fi := range candidateFingers {
			engine.HTTPFingers[fi].PassiveMatch(content)
		}
	}
}

// ──────────────────────────────────────────────────────────────
// 8. Content size scaling analysis
// ──────────────────────────────────────────────────────────────

func TestContentSizeScaling(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping heavy performance comparison in short mode")
	}
	engine := newPerfEngine(t)
	acIdx := buildACIndex(engine.HTTPFingers)

	sizes := []int{1024, 4096, 16384, 65536, 262144}
	const iterations = 50

	t.Logf("%-10s %15s %15s %10s", "Size", "Baseline", "AC", "Speedup")
	t.Logf(strings.Repeat("-", 55))

	for _, size := range sizes {
		raw := generateLargeResponse(size)
		content := NewContent(raw, "", true)

		// baseline
		runtime.GC()
		baseStart := time.Now()
		for i := 0; i < iterations; i++ {
			engine.HTTPMatch(raw, "")
		}
		baseElapsed := time.Since(baseStart) / time.Duration(iterations)

		// AC
		runtime.GC()
		acStart := time.Now()
		for i := 0; i < iterations; i++ {
			acResults := acIdx.matchKeywords(content.Header, content.Body)
			candidateFingers := make(map[int]bool)
			for _, r := range acResults {
				candidateFingers[r.FingerIdx] = true
			}
			for fi, finger := range engine.HTTPFingers {
				if candidateFingers[fi] {
					continue
				}
				for _, rule := range finger.Rules {
					if rule.Regexps == nil {
						continue
					}
					if len(rule.Regexps.CompliedRegexp) > 0 || len(rule.Regexps.CompiledVulnRegexp) > 0 ||
						len(rule.Regexps.MD5) > 0 || len(rule.Regexps.MMH3) > 0 {
						candidateFingers[fi] = true
						break
					}
				}
			}
			for fi := range candidateFingers {
				engine.HTTPFingers[fi].PassiveMatch(content)
			}
		}
		acElapsed := time.Since(acStart) / time.Duration(iterations)

		_ = acStart
		speedup := float64(baseElapsed) / float64(acElapsed)
		t.Logf("%-10d %15s %15s %9.2fx", size, baseElapsed, acElapsed, speedup)
	}
}

// ──────────────────────────────────────────────────────────────
// 9. AC build cost analysis
// ──────────────────────────────────────────────────────────────

func TestACBuildCost(t *testing.T) {
	engine := newPerfEngine(t)

	start := time.Now()
	acIdx := buildACIndex(engine.HTTPFingers)
	buildTime := time.Since(start)

	t.Logf("AC build time: %s", buildTime)
	t.Logf("Body patterns: %d, Header patterns: %d", len(acIdx.bodyPatterns), len(acIdx.headerPatterns))

	// Single match warmup + timing
	raw := generateLargeResponse(16 * 1024)
	content := NewContent(raw, "", true)

	matchStart := time.Now()
	results := acIdx.matchKeywords(content.Header, content.Body)
	matchTime := time.Since(matchStart)

	t.Logf("Single AC match time: %s, hits: %d", matchTime, len(results))
	t.Logf("Build amortized over 1000 matches: %s per match", buildTime/1000)
}

// ──────────────────────────────────────────────────────────────
// 10. Go stdlib regexp vs go-re2 (C wrapper) comparison
// ──────────────────────────────────────────────────────────────

func TestGoRegexpVsRE2(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping heavy performance comparison in short mode")
	}
	engine := newPerfEngine(t)

	type patternPair struct {
		goRe  *regexp.Regexp
		re2Re *re2.Regexp
		src   string
	}

	var patterns []patternPair
	for _, finger := range engine.HTTPFingers {
		for _, rule := range finger.Rules {
			if rule.Regexps == nil {
				continue
			}
			for _, r := range rule.Regexps.CompliedRegexp {
				src := r.String()
				goRe, err := regexp.Compile(src)
				if err != nil {
					continue
				}
				re2Re, err := re2.Compile(src)
				if err != nil {
					t.Logf("SKIP re2 compile %q: %v", src, err)
					continue
				}
				patterns = append(patterns, patternPair{goRe: goRe, re2Re: re2Re, src: src})
			}
			for _, r := range rule.Regexps.CompiledVulnRegexp {
				src := r.String()
				goRe, err := regexp.Compile(src)
				if err != nil {
					continue
				}
				re2Re, err := re2.Compile(src)
				if err != nil {
					t.Logf("SKIP re2 compile %q: %v", src, err)
					continue
				}
				patterns = append(patterns, patternPair{goRe: goRe, re2Re: re2Re, src: src})
			}
		}
	}
	t.Logf("Compiled %d patterns for both engines", len(patterns))

	sizes := []int{1024, 8192, 32768, 131072}
	const iterations = 20

	for _, size := range sizes {
		content := NewContent(generateLargeResponse(size), "", true)

		// Go stdlib
		runtime.GC()
		goStart := time.Now()
		goHits := 0
		for i := 0; i < iterations; i++ {
			for _, p := range patterns {
				if p.goRe.Match(content.Content) {
					goHits++
				}
			}
		}
		goElapsed := time.Since(goStart) / time.Duration(iterations)

		// go-re2
		runtime.GC()
		re2Start := time.Now()
		re2Hits := 0
		for i := 0; i < iterations; i++ {
			for _, p := range patterns {
				if p.re2Re.Match(content.Content) {
					re2Hits++
				}
			}
		}
		re2Elapsed := time.Since(re2Start) / time.Duration(iterations)

		speedup := float64(goElapsed) / float64(re2Elapsed)
		t.Logf("[%dB] go_regexp=%s(%d) re2=%s(%d) speedup=%.2fx",
			size, goElapsed, goHits/iterations, re2Elapsed, re2Hits/iterations, speedup)
	}
}

func BenchmarkRegexp_RE2(b *testing.B) {
	engine := newPerfEngine(b)
	var re2Regexps []*re2.Regexp
	for _, finger := range engine.HTTPFingers {
		for _, rule := range finger.Rules {
			if rule.Regexps == nil {
				continue
			}
			for _, r := range rule.Regexps.CompliedRegexp {
				re2r, err := re2.Compile(r.String())
				if err != nil {
					continue
				}
				re2Regexps = append(re2Regexps, re2r)
			}
			for _, r := range rule.Regexps.CompiledVulnRegexp {
				re2r, err := re2.Compile(r.String())
				if err != nil {
					continue
				}
				re2Regexps = append(re2Regexps, re2r)
			}
		}
	}

	content := NewContent(generateLargeResponse(32*1024), "", true)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, r := range re2Regexps {
			r.Match(content.Content)
		}
	}
}

// ──────────────────────────────────────────────────────────────
// 11. Combined AC + RE2 full optimization
// ──────────────────────────────────────────────────────────────

func TestCombinedOptimization(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping heavy performance comparison in short mode")
	}
	engine := newPerfEngine(t)
	acIdx := buildACIndex(engine.HTTPFingers)

	// Pre-compile re2 versions of all regex patterns
	type re2RulePatterns struct {
		regexps     []*re2.Regexp
		vulnRegexps []*re2.Regexp
	}
	re2Cache := make(map[*Rule]*re2RulePatterns)
	for _, finger := range engine.HTTPFingers {
		for _, rule := range finger.Rules {
			if rule.Regexps == nil {
				continue
			}
			rp := &re2RulePatterns{}
			for _, r := range rule.Regexps.CompliedRegexp {
				re2r, err := re2.Compile(r.String())
				if err == nil {
					rp.regexps = append(rp.regexps, re2r)
				}
			}
			for _, r := range rule.Regexps.CompiledVulnRegexp {
				re2r, err := re2.Compile(r.String())
				if err == nil {
					rp.vulnRegexps = append(rp.vulnRegexps, re2r)
				}
			}
			re2Cache[rule] = rp
		}
	}

	sites := generateSyntheticResponses()
	realSites := loadTestSites(t)
	sites = append(sites, realSites...)

	iterations := 50
	for _, site := range sites {
		if len(site.Content) > 300000 {
			iterations = 10
		}

		content := NewContent(site.Content, "", true)

		// Baseline
		runtime.GC()
		baseStart := time.Now()
		var baseFrames int
		for i := 0; i < iterations; i++ {
			fs, _ := engine.HTTPMatch(site.Content, "")
			baseFrames = len(fs)
		}
		baseElapsed := time.Since(baseStart) / time.Duration(iterations)

		// AC + RE2 combined
		runtime.GC()
		optStart := time.Now()
		var optFrames int
		for i := 0; i < iterations; i++ {
			// Phase 1: AC keyword scan
			acResults := acIdx.matchKeywords(content.Header, content.Body)
			matched := make(map[int]bool)
			for _, r := range acResults {
				matched[r.FingerIdx] = true
			}

			// Phase 2: RE2 regex scan for fingerprints with regex-only rules
			for fi, finger := range engine.HTTPFingers {
				if matched[fi] {
					continue
				}
				for _, rule := range finger.Rules {
					if rule.Regexps == nil {
						continue
					}
					rp := re2Cache[rule]
					if rp == nil {
						continue
					}
					hit := false
					for _, r := range rp.vulnRegexps {
						if r.Match(content.Content) {
							hit = true
							break
						}
					}
					if !hit {
						for _, r := range rp.regexps {
							if r.Match(content.Content) {
								hit = true
								break
							}
						}
					}
					if hit {
						matched[fi] = true
						break
					}
				}
			}

			count := 0
			for fi := range matched {
				finger := engine.HTTPFingers[fi]
				_, _, ok := finger.PassiveMatch(content)
				if ok {
					count++
				}
			}
			optFrames = count
		}
		optElapsed := time.Since(optStart) / time.Duration(iterations)

		speedup := float64(baseElapsed) / float64(optElapsed)
		t.Logf("[%s] %dB: baseline=%s(%d) AC+RE2=%s(%d) speedup=%.2fx",
			site.Name, len(site.Content), baseElapsed, baseFrames, optElapsed, optFrames, speedup)
	}
}
