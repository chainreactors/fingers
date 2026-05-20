package xray

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chainreactors/fingers/resources"
)

func TestScanRange(t *testing.T) {
	engine, err := NewXrayEngine(resources.XrayWebData)
	if err != nil {
		t.Fatalf("load engine: %v", err)
	}
	t.Logf("Loaded %d templates", engine.Len())

	// Generate targets
	var targets []string
	for i := 1; i < 255; i++ {
		ip := fmt.Sprintf("101.132.149.%d", i)
		targets = append(targets, fmt.Sprintf("http://%s", ip))
		targets = append(targets, fmt.Sprintf("https://%s", ip))
	}

	// Probe alive
	t.Log("Probing...")
	alive := probeAlive(targets, 3*time.Second, 50)
	t.Logf("Alive: %d / %d", len(alive), len(targets))
	if len(alive) == 0 {
		t.Skip("No alive targets")
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	type result struct {
		URL    string
		Frames []string
	}
	var mu sync.Mutex
	var results []result
	sem := make(chan struct{}, 20)
	var wg sync.WaitGroup

	for _, target := range alive {
		wg.Add(1)
		sem <- struct{}{}
		go func(url string) {
			defer wg.Done()
			defer func() { <-sem }()

			resp, err := client.Get(url)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			body, _ := ioutil.ReadAll(resp.Body)

			// Build raw HTTP response for WebMatch
			raw := buildRawResponse(resp, body)
			frames := engine.WebMatch(raw)

			if len(frames) > 0 {
				var names []string
				for _, f := range frames {
					names = append(names, f.Name)
				}
				sort.Strings(names)
				mu.Lock()
				results = append(results, result{URL: url, Frames: names})
				mu.Unlock()
			}
		}(target)
	}
	wg.Wait()

	sort.Slice(results, func(i, j int) bool { return results[i].URL < results[j].URL })

	// Print results
	t.Logf("\n=== Fingerprint Results (%d hits) ===", len(results))
	for _, r := range results {
		t.Logf("  %-45s %s", r.URL, strings.Join(r.Frames, ", "))
	}

	// Analyze: find fingerprints that appear on too many targets (potential FP)
	fpCount := map[string]int{}
	for _, r := range results {
		for _, f := range r.Frames {
			fpCount[f]++
		}
	}
	type kv struct {
		k string
		v int
	}
	var sorted []kv
	for k, v := range fpCount {
		sorted = append(sorted, kv{k, v})
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].v > sorted[j].v })

	t.Logf("\n=== Fingerprint Frequency (potential FP if too high) ===")
	for _, s := range sorted {
		tag := ""
		if s.v > len(results)/3 {
			tag = " *** SUSPICIOUS"
		}
		t.Logf("  %4d  %s%s", s.v, s.k, tag)
	}
}

func buildRawResponse(resp *http.Response, body []byte) []byte {
	var buf strings.Builder
	buf.WriteString(fmt.Sprintf("HTTP/1.1 %s\r\n", resp.Status))
	for k, vals := range resp.Header {
		for _, v := range vals {
			buf.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
		}
	}
	buf.WriteString("\r\n")
	buf.Write(body)
	return []byte(buf.String())
}

func probeAlive(targets []string, timeout time.Duration, conc int) []string {
	var alive []string
	var mu sync.Mutex
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup
	for _, target := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(url string) {
			defer wg.Done()
			defer func() { <-sem }()
			host := strings.TrimPrefix(strings.TrimPrefix(url, "http://"), "https://")
			port := "80"
			if strings.HasPrefix(url, "https://") {
				port = "443"
			}
			conn, err := net.DialTimeout("tcp", host+":"+port, timeout)
			if err != nil {
				return
			}
			conn.Close()
			mu.Lock()
			alive = append(alive, url)
			mu.Unlock()
		}(target)
	}
	wg.Wait()
	return alive
}
