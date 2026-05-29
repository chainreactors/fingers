package fingers

import (
	"bytes"
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
	"github.com/chainreactors/fingers/xray"
)

func TestCompareEngines(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live network test in short mode")
	}
	fullEngine, err := NewEngine(FingersEngine, FingerPrintEngine, EHoleEngine, GobyEngine)
	if err != nil {
		t.Fatalf("init engine: %v", err)
	}
	t.Logf("Engines: %s", fullEngine)

	xrayEng, err := xray.NewXrayEngine(resources.XrayWebData)
	if err != nil {
		t.Fatalf("init xray: %v", err)
	}
	t.Logf("Xray templates: %d", xrayEng.Len())

	var targets []string
	for i := 1; i < 255; i++ {
		ip := fmt.Sprintf("101.132.149.%d", i)
		targets = append(targets, fmt.Sprintf("http://%s", ip))
		targets = append(targets, fmt.Sprintf("https://%s", ip))
	}

	alive := probeAlive(targets, 3*time.Second, 50)
	t.Logf("Alive: %d", len(alive))

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

	type targetResult struct {
		URL        string
		OtherFP    []string
		XrayFP     []string
		MissInXray []string
	}

	var mu sync.Mutex
	var results []targetResult
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
			raw := buildRawHTTP2(resp, body)

			// Other engines (exclude xray and favicon)
			otherFrames := fullEngine.WebMatchWithEngines(raw,
				FingersEngine, FingerPrintEngine, EHoleEngine, GobyEngine)

			// Xray engine
			xrayFrames := xrayEng.WebMatch(raw)

			if len(otherFrames) == 0 && len(xrayFrames) == 0 {
				return
			}

			otherSet := map[string]bool{}
			var otherNames []string
			for _, f := range otherFrames {
				otherSet[strings.ToLower(f.Name)] = true
				otherNames = append(otherNames, f.Name)
			}
			sort.Strings(otherNames)

			xraySet := map[string]bool{}
			var xrayNames []string
			for _, f := range xrayFrames {
				xraySet[strings.ToLower(f.Name)] = true
				xrayNames = append(xrayNames, f.Name)
			}
			sort.Strings(xrayNames)

			var missInXray []string
			for name := range otherSet {
				if !xraySet[name] {
					missInXray = append(missInXray, name)
				}
			}
			sort.Strings(missInXray)

			mu.Lock()
			results = append(results, targetResult{
				URL: url, OtherFP: otherNames, XrayFP: xrayNames, MissInXray: missInXray,
			})
			mu.Unlock()
		}(target)
	}
	wg.Wait()
	sort.Slice(results, func(i, j int) bool { return results[i].URL < results[j].URL })

	// Aggregate
	missCount := map[string]int{}
	missTargets := 0
	for _, r := range results {
		if len(r.MissInXray) > 0 {
			missTargets++
		}
		for _, name := range r.MissInXray {
			missCount[name]++
		}
	}

	t.Logf("\n=== Engine Comparison ===")
	totalOther, totalXray := 0, 0
	for _, r := range results {
		if len(r.OtherFP) > 0 { totalOther++ }
		if len(r.XrayFP) > 0 { totalXray++ }
	}
	t.Logf("Targets with other-engine FP: %d", totalOther)
	t.Logf("Targets with xray FP:         %d", totalXray)
	t.Logf("Targets with xray miss:       %d", missTargets)

	t.Logf("\n--- Missed in Xray (detected by other engines) ---")
	type kv struct{ k string; v int }
	var sorted []kv
	for k, v := range missCount {
		sorted = append(sorted, kv{k, v})
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].v > sorted[j].v })
	for _, s := range sorted {
		t.Logf("  %4d  %s", s.v, s.k)
	}

	t.Logf("\n--- Per-Target Details (first 30 with misses) ---")
	shown := 0
	for _, r := range results {
		if len(r.MissInXray) == 0 {
			continue
		}
		t.Logf("  %-40s other=[%s] xray=[%s] miss=[%s]",
			r.URL,
			strings.Join(r.OtherFP, ","),
			strings.Join(r.XrayFP, ","),
			strings.Join(r.MissInXray, ","))
		shown++
		if shown >= 30 {
			break
		}
	}
}

func buildRawHTTP2(resp *http.Response, body []byte) []byte {
	var buf bytes.Buffer
	buf.WriteString(fmt.Sprintf("%s %s\r\n", resp.Proto, resp.Status))
	for k, vals := range resp.Header {
		for _, v := range vals {
			buf.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
		}
	}
	buf.WriteString("\r\n")
	buf.Write(body)
	return buf.Bytes()
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
