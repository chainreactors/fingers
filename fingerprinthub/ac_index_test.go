package fingerprinthub

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chainreactors/fingers/common"
	"github.com/chainreactors/fingers/resources"
	"github.com/chainreactors/utils/httputils"
)

func TestTemplateKeywordIndex_Build(t *testing.T) {
	engine, err := NewFingerPrintHubEngine(resources.FingerprinthubWebData, resources.FingerprinthubServiceData)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	idx := engine.webTemplateIndex
	if idx == nil {
		t.Fatal("webTemplateIndex is nil")
	}

	totalTemplates := len(engine.webTemplates)
	fastPathCount := len(idx.fastPath)

	t.Logf("Total web templates: %d", totalTemplates)
	t.Logf("Fast-path templates (direct AC resolution): %d (%.1f%%)", fastPathCount, float64(fastPathCount)/float64(totalTemplates)*100)

	if fastPathCount == 0 {
		t.Error("No fast-path templates — unified matching provides no benefit")
	}
}

func TestTemplateKeywordIndex_Match(t *testing.T) {
	engine, err := NewFingerPrintHubEngine(resources.FingerprinthubWebData, resources.FingerprinthubServiceData)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	testBody := "powered by wordpress"
	testHeader := "server: nginx\ncontent-type: text/html\n"

	mr := engine.webTemplateIndex.Match(testHeader, testBody)
	totalCandidates := len(mr.Matched) + len(mr.NeedsCheck)
	totalTemplates := len(engine.webTemplates)

	t.Logf("Matched (fast-path): %d", len(mr.Matched))
	t.Logf("NeedsCheck (slow-path): %d", len(mr.NeedsCheck))
	t.Logf("Total candidates: %d / %d (%.1f%% filtered)",
		totalCandidates, totalTemplates,
		float64(totalTemplates-totalCandidates)/float64(totalTemplates)*100)

	if totalCandidates >= totalTemplates {
		t.Error("AC index did not filter any templates")
	}
}

// webMatchBaseline runs the original full-iteration WebMatch logic without AC prefiltering.
func (engine *FingerPrintHubEngine) webMatchBaseline(content []byte) common.Frameworks {
	resp := httputils.NewResponseWithRaw(content)
	if resp == nil {
		return make(common.Frameworks)
	}

	rawBody := httputils.ReadBody(resp)
	rawBodyStr := string(rawBody)
	event := engine.buildInternalEvent(resp, rawBodyStr, len(content))
	frames := make(common.Frameworks)

	for _, tmpl := range engine.webTemplates {
		requests := tmpl.GetRequests()
		if len(requests) == 0 {
			continue
		}
		for _, req := range requests {
			if req.Matchers == nil || len(req.Matchers) == 0 {
				continue
			}
			matched := engine.matchRequest(req, event)
			if matched {
				name := tmpl.Info.Name
				if name == "" {
					name = tmpl.Id
				}
				frame := common.NewFramework(name, common.FrameFromFingerprintHub)
				if tmpl.Info.Metadata != nil {
					if vendor, ok := tmpl.Info.Metadata["vendor"].(string); ok {
						frame.Attributes.Vendor = vendor
					}
					if product, ok := tmpl.Info.Metadata["product"].(string); ok {
						frame.Attributes.Product = product
					}
				}
				frames.Add(frame)
				break
			}
		}
	}
	return frames
}

func frameworkNames(f common.Frameworks) []string {
	var names []string
	for name := range f {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func TestWebMatchConsistency_Static(t *testing.T) {
	engine, err := NewFingerPrintHubEngine(resources.FingerprinthubWebData, resources.FingerprinthubServiceData)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	responses := []struct {
		name string
		raw  string
	}{
		{
			"nginx",
			"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Type: text/html\r\n\r\n<html><body>Welcome to nginx!</body></html>",
		},
		{
			"apache",
			"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\nContent-Type: text/html\r\n\r\n<html><body>It works!</body></html>",
		},
		{
			"wordpress",
			"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/html\r\n\r\n<html><head><meta name=\"generator\" content=\"WordPress 5.8\" /></head><body>Blog</body></html>",
		},
		{
			"empty",
			"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body>Hello</body></html>",
		},
	}

	for _, tc := range responses {
		t.Run(tc.name, func(t *testing.T) {
			content := []byte(tc.raw)

			baseline := engine.webMatchBaseline(content)
			optimized := engine.WebMatch(content)

			baseNames := frameworkNames(baseline)
			optNames := frameworkNames(optimized)

			if len(baseNames) != len(optNames) {
				t.Errorf("Result count mismatch: baseline=%d optimized=%d", len(baseNames), len(optNames))
				t.Logf("Baseline:  %v", baseNames)
				t.Logf("Optimized: %v", optNames)
				return
			}

			for i := range baseNames {
				if baseNames[i] != optNames[i] {
					t.Errorf("Framework name mismatch at %d: baseline=%q optimized=%q", i, baseNames[i], optNames[i])
				}
			}

			t.Logf("Matched %d frameworks: %v", len(baseNames), baseNames)
		})
	}
}

func fetchRawResponse(host string, port int, useTLS bool) ([]byte, error) {
	addr := fmt.Sprintf("%s:%d", host, port)
	scheme := "http"
	if useTLS {
		scheme = "https"
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			DialContext: (&net.Dialer{
				Timeout: 3 * time.Second,
			}).DialContext,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get(fmt.Sprintf("%s://%s/", scheme, addr))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	buf.WriteString(fmt.Sprintf("HTTP/%d.%d %d %s\r\n", resp.ProtoMajor, resp.ProtoMinor, resp.StatusCode, resp.Status))
	for key, values := range resp.Header {
		for _, val := range values {
			buf.WriteString(fmt.Sprintf("%s: %s\r\n", key, val))
		}
	}
	buf.WriteString("\r\n")
	buf.Write(bodyBytes)

	return buf.Bytes(), nil
}

type collectedResponse struct {
	label   string // "host:port"
	content []byte
}

// collectResponses fetches HTTP responses from a /24 subnet on given ports.
// Network errors are silently skipped; only successful responses are returned.
func collectResponses(baseIP string, ports []int, concurrency int) []collectedResponse {
	ip := net.ParseIP(baseIP).To4()
	if ip == nil {
		return nil
	}

	type result struct {
		label   string
		content []byte
	}
	ch := make(chan result, 512)
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for i := 0; i < 256; i++ {
		targetIP := make(net.IP, 4)
		copy(targetIP, ip)
		targetIP[3] = byte(i)
		host := targetIP.String()
		for _, port := range ports {
			wg.Add(1)
			go func(h string, p int) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				content, err := fetchRawResponse(h, p, p == 443)
				if err != nil {
					return
				}
				ch <- result{fmt.Sprintf("%s:%d", h, p), content}
			}(host, port)
		}
	}
	go func() { wg.Wait(); close(ch) }()

	var out []collectedResponse
	for r := range ch {
		out = append(out, collectedResponse{r.label, r.content})
	}
	return out
}

// TestWebMatchConsistency_Live collects real responses then verifies
// baseline and optimized WebMatch produce identical results.
func TestWebMatchConsistency_Live(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live network test in short mode")
	}

	t.Log("Phase 1: collecting responses from 101.132.149.35/24 :80,:443 ...")
	responses := collectResponses("101.132.149.35", []int{80, 443}, 50)
	t.Logf("Collected %d responses", len(responses))
	if len(responses) == 0 {
		t.Skip("no live hosts responded")
	}

	t.Log("Phase 2: matching (baseline vs optimized) ...")
	engine, err := NewFingerPrintHubEngine(resources.FingerprinthubWebData, resources.FingerprinthubServiceData)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	var totalMismatch int
	for _, resp := range responses {
		baseline := engine.webMatchBaseline(resp.content)
		optimized := engine.WebMatch(resp.content)

		baseNames := frameworkNames(baseline)
		optNames := frameworkNames(optimized)

		if strings.Join(baseNames, ",") != strings.Join(optNames, ",") {
			totalMismatch++
			t.Errorf("[%s] MISMATCH baseline=%v optimized=%v", resp.label, baseNames, optNames)
		} else if len(baseNames) > 0 {
			t.Logf("[%s] OK %v", resp.label, baseNames)
		}
	}

	t.Logf("Checked: %d, Mismatches: %d", len(responses), totalMismatch)
	if totalMismatch > 0 {
		t.Errorf("%d mismatches found", totalMismatch)
	}
}

// TestWebMatchBenchmark_Live collects real responses then benchmarks
// baseline vs optimized matching, measuring ONLY match time.
func TestWebMatchBenchmark_Live(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live benchmark in short mode")
	}

	t.Log("Phase 1: collecting responses from 101.132.149.35/24 :80,:443 ...")
	responses := collectResponses("101.132.149.35", []int{80, 443}, 50)
	t.Logf("Collected %d responses\n", len(responses))
	if len(responses) == 0 {
		t.Skip("no live hosts responded")
	}

	engine, err := NewFingerPrintHubEngine(resources.FingerprinthubWebData, resources.FingerprinthubServiceData)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	const rounds = 3

	// Baseline: iterate all 3138 templates per response
	t.Log("Phase 2: baseline matching (full iteration) ...")
	var baselineTotal time.Duration
	var baselineFrameworks int
	for r := 0; r < rounds; r++ {
		start := time.Now()
		for _, resp := range responses {
			frames := engine.webMatchBaseline(resp.content)
			baselineFrameworks += len(frames)
		}
		baselineTotal += time.Since(start)
	}
	baselineAvg := baselineTotal / time.Duration(rounds)
	baselinePerResp := baselineAvg / time.Duration(len(responses))

	// Optimized: AC unified matching
	t.Log("Phase 3: optimized matching (AC unified) ...")
	var optimizedTotal time.Duration
	var optimizedFrameworks int
	for r := 0; r < rounds; r++ {
		start := time.Now()
		for _, resp := range responses {
			frames := engine.WebMatch(resp.content)
			optimizedFrameworks += len(frames)
		}
		optimizedTotal += time.Since(start)
	}
	optimizedAvg := optimizedTotal / time.Duration(rounds)
	optimizedPerResp := optimizedAvg / time.Duration(len(responses))

	speedup := float64(baselineAvg) / float64(optimizedAvg)

	t.Log("")
	t.Log("========== Results ==========")
	t.Logf("Responses:       %d", len(responses))
	t.Logf("Rounds:          %d", rounds)
	t.Log("")
	t.Logf("Baseline total:  %v  (per response: %v)", baselineAvg, baselinePerResp)
	t.Logf("Optimized total: %v  (per response: %v)", optimizedAvg, optimizedPerResp)
	t.Logf("Speedup:         %.1fx", speedup)
	t.Log("")
	t.Logf("Frameworks found (baseline):  %d", baselineFrameworks/rounds)
	t.Logf("Frameworks found (optimized): %d", optimizedFrameworks/rounds)

	if baselineFrameworks != optimizedFrameworks {
		t.Errorf("Framework count mismatch across %d rounds: baseline=%d optimized=%d",
			rounds, baselineFrameworks, optimizedFrameworks)
	}
}
