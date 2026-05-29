package fingers

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chainreactors/fingers/resources"
)

var (
	cachedResponses     map[string][]byte
	cachedResponsesOnce sync.Once
)

func fetchAndCache(targets []string) map[string][]byte {
	cachedResponsesOnce.Do(func() {
		cachedResponses = make(map[string][]byte)
		cacheDir := filepath.Join(os.TempDir(), "fingers_bench_cache")
		os.MkdirAll(cacheDir, 0755)

		client := &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
				DisableKeepAlives: true,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		var mu sync.Mutex
		var wg sync.WaitGroup
		sem := make(chan struct{}, 20)

		for _, target := range targets {
			wg.Add(1)
			go func(t string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				cacheKey := strings.ReplaceAll(strings.ReplaceAll(t, "://", "_"), "/", "_")
				cacheFile := filepath.Join(cacheDir, cacheKey)

				if data, err := os.ReadFile(cacheFile); err == nil && len(data) > 0 {
					mu.Lock()
					cachedResponses[t] = data
					mu.Unlock()
					return
				}

				resp, err := client.Get(t)
				if err != nil {
					return
				}
				defer resp.Body.Close()
				body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
				if err != nil || len(body) == 0 {
					return
				}

				var sb strings.Builder
				sb.WriteString(fmt.Sprintf("HTTP/%d.%d %s\r\n", resp.ProtoMajor, resp.ProtoMinor, resp.Status))
				for k, vs := range resp.Header {
					for _, v := range vs {
						sb.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
					}
				}
				sb.WriteString("\r\n")
				sb.Write(body)

				raw := []byte(sb.String())
				os.WriteFile(cacheFile, raw, 0644)
				mu.Lock()
				cachedResponses[t] = raw
				mu.Unlock()
			}(target)
		}
		wg.Wait()
	})
	return cachedResponses
}

func expandCIDR(cidr string, ports []int) []string {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil
	}
	var targets []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
		for _, port := range ports {
			scheme := "http"
			if port == 443 || port == 8443 {
				scheme = "https"
			}
			targets = append(targets, fmt.Sprintf("%s://%s:%d/", scheme, ip.String(), port))
		}
	}
	return targets
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func newRealSiteEngine(tb testing.TB) *FingersEngine {
	tb.Helper()
	engine, err := NewFingersEngine(resources.FingersHTTPData, resources.FingersSocketData, resources.PortData)
	if err != nil {
		tb.Fatalf("create engine: %v", err)
	}
	return engine
}

// BenchmarkRealSites compares AC-accelerated matching vs brute-force PassiveMatch
// on real HTTP responses from a /26 CIDR range.
func BenchmarkRealSites(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping live network benchmark in short mode")
	}
	targets := expandCIDR("101.132.149.35/26", []int{80, 443})
	responses := fetchAndCache(targets)
	if len(responses) == 0 {
		b.Skip("no responses fetched")
	}

	engine := newRealSiteEngine(b)

	type testCase struct {
		url     string
		data    []byte
		content *Content
	}
	var cases []testCase
	for url, data := range responses {
		cases = append(cases, testCase{
			url:     url,
			data:    data,
			content: NewContent(data, "", true),
		})
	}

	totalBytes := 0
	for _, c := range cases {
		totalBytes += len(c.data)
	}
	b.Logf("%d responses, %d bytes total, %d fingerprint rules",
		len(cases), totalBytes, len(engine.HTTPFingers))

	// With AC pre-filtering (current optimized path)
	b.Run("WithAC", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(totalBytes))
		for i := 0; i < b.N; i++ {
			for _, c := range cases {
				engine.HTTPFingers.ACPassiveMatch(c.content, engine.httpKeywordIndex, false)
			}
		}
	})

	// Without AC - brute force all fingerprints
	b.Run("WithoutAC", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(totalBytes))
		for i := 0; i < b.N; i++ {
			for _, c := range cases {
				engine.HTTPFingers.PassiveMatch(c.content, false)
			}
		}
	})

	// AC MatchCandidates only (pure AC cost)
	b.Run("ACOnly", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(totalBytes))
		for i := 0; i < b.N; i++ {
			for _, c := range cases {
				engine.httpKeywordIndex.MatchCandidates(c.content.Header, c.content.Body)
			}
		}
	})

	// Full HTTPMatch (includes Content parsing overhead)
	b.Run("FullHTTPMatch", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(totalBytes))
		for i := 0; i < b.N; i++ {
			for _, c := range cases {
				engine.HTTPMatch(c.data, "")
			}
		}
	})
}

func TestRealSites_Correctness(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live network test in short mode")
	}
	targets := expandCIDR("101.132.149.35/26", []int{80, 443})
	responses := fetchAndCache(targets)
	if len(responses) == 0 {
		t.Skip("no responses fetched")
	}

	engine := newRealSiteEngine(t)

	for url, data := range responses {
		content := NewContent(data, "", true)
		withAC, _ := engine.HTTPFingers.ACPassiveMatch(content, engine.httpKeywordIndex, false)
		withoutAC, _ := engine.HTTPFingers.PassiveMatch(content, false)

		acNames := make([]string, 0)
		for _, f := range withAC {
			acNames = append(acNames, f.Name)
		}
		noACNames := make([]string, 0)
		for _, f := range withoutAC {
			noACNames = append(noACNames, f.Name)
		}

		if len(acNames) > 0 || len(noACNames) > 0 {
			t.Logf("%-40s AC:[%s]  NoAC:[%s]", url,
				strings.Join(acNames, ","), strings.Join(noACNames, ","))
		}

		// Verify AC doesn't miss any matches
		noACSet := make(map[string]bool)
		for _, n := range noACNames {
			noACSet[n] = true
		}
		for _, n := range acNames {
			if !noACSet[n] {
				// AC found something PassiveMatch didn't - that's fine (AC includes nonKeyword fingers)
			}
		}
		acSet := make(map[string]bool)
		for _, n := range acNames {
			acSet[n] = true
		}
		for _, n := range noACNames {
			if !acSet[n] {
				t.Errorf("%s: AC missed fingerprint %q found by PassiveMatch", url, n)
			}
		}
	}
}
