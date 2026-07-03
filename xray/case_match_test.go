package xray

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chainreactors/fingers/common"
	"gopkg.in/yaml.v3"
)

const templatesDir = "../bin/templates"

func loadAllTemplates(t *testing.T) *XrayEngine {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(templatesDir, "*.yaml"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(files) == 0 {
		t.Fatalf("no yaml in %s", templatesDir)
	}

	var docs []map[string]interface{}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		dec := yaml.NewDecoder(strings.NewReader(string(data)))
		for {
			var doc map[string]interface{}
			if err := dec.Decode(&doc); err != nil {
				break
			}
			if doc != nil {
				docs = append(docs, doc)
			}
		}
	}

	js, _ := json.Marshal(docs)
	engine, err := NewXrayEngine(nil)
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	if err := engine.LoadFromJSON(js); err != nil {
		t.Fatalf("load: %v", err)
	}
	t.Logf("loaded %d templates from %s", engine.Len(), templatesDir)
	return engine
}

func makeTransport() *http.Transport {
	return &http.Transport{
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives:     true,
		ResponseHeaderTimeout: 10 * time.Second,
		DialContext: (&net.Dialer{
			Timeout: 5 * time.Second,
		}).DialContext,
	}
}

func makeClient() *http.Client {
	return &http.Client{
		Timeout:   15 * time.Second,
		Transport: makeTransport(),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

type testCase struct {
	Name     string
	URL      string
	Keywords []string
}

var testCases = []testCase{
	{"Apache-APISIX", "https://m.client.10010.com", []string{"apisix"}},
	{"Smartbi", "https://report.gxjettoll.cn:8443", []string{"smartbi"}},
	{"Microsoft-Exchange", "http://autodiscover.365.sh.jcy.cn", []string{"exchange"}},
	{"TRS-MAS", "https://36.136.118.32:9001", []string{"mas", "拓尔思"}},
	{"Yonyou-OA-GRPU8", "http://210.36.247.224:6901", []string{"用友", "grp", "oa", "yonyou"}},
}

func TestCaseMatch(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live network test in short mode")
	}
	engine := loadAllTemplates(t)

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			t.Logf("baseURL: %s", tc.URL)

			// --- passive: fetch 根路径响应, WebMatch ---
			t.Run("passive", func(t *testing.T) {
				resp, err := makeClient().Get(tc.URL + "/")
				if err != nil {
					t.Skipf("fetch failed: %v", err)
				}
				defer resp.Body.Close()
				body, _ := ioutil.ReadAll(resp.Body)
				raw := rebuildRaw(resp, body)
				t.Logf("HTTP %d, %d bytes body, headers:", resp.StatusCode, len(body))
				for k, v := range resp.Header {
					t.Logf("  %s: %s", k, strings.Join(v, "; "))
				}

				frames := engine.WebMatch(raw)
				printFrames(t, frames)
				if !hit(frames, tc.Keywords) {
					t.Errorf("passive 未识别出 %v", tc.Keywords)
				}
			})

			// --- active: HTTPActiveMatch, neutron 按模板路径自动发包 ---
			t.Run("active", func(t *testing.T) {
				frames, _ := engine.HTTPActiveMatch(tc.URL, 1, makeTransport(),
					func(f *common.Framework, v *common.Vuln) {
						t.Logf("  active hit: %s", f.Name)
					})
				printFrames(t, frames)
				if !hit(frames, tc.Keywords) {
					t.Errorf("active 未识别出 %v", tc.Keywords)
				}
			})
		})
	}
}

func extractBase(u string) string {
	i := strings.Index(u, "://")
	if i < 0 {
		return u
	}
	rest := u[i+3:]
	if j := strings.Index(rest, "/"); j >= 0 {
		return u[:i+3+j]
	}
	return u
}

func rebuildRaw(resp *http.Response, body []byte) []byte {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("HTTP/1.1 %s\r\n", resp.Status))
	for k, vals := range resp.Header {
		for _, v := range vals {
			b.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
		}
	}
	b.WriteString("\r\n")
	b.Write(body)
	return []byte(b.String())
}

func printFrames(t *testing.T, frames common.Frameworks) {
	t.Helper()
	t.Logf("matched %d frameworks:", len(frames))
	for _, f := range frames {
		t.Logf("  → %s (from=%s vendor=%q product=%q)", f.Name, f.From, f.Vendor, f.Product)
	}
}

func hit(frames common.Frameworks, keywords []string) bool {
	for _, f := range frames {
		low := strings.ToLower(f.Name)
		for _, kw := range keywords {
			if strings.Contains(low, strings.ToLower(kw)) {
				return true
			}
		}
	}
	return false
}
