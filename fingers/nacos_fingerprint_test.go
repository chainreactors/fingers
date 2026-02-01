package fingers

import (
	"crypto/tls"
	"net/http"
	"testing"
	"time"

	"github.com/chainreactors/utils/encode"
	"github.com/chainreactors/utils/httputils"
	"gopkg.in/yaml.v3"
)

func TestNacosFingerprint_RealSite(t *testing.T) {
	const (
		baseURL         = "https://nacos.lzfzkj.com"
		fingerSendPath  = "/nacos/"
		faviconSendPath = "/nacos/console-ui/public/img/nacos-logo.png"
		expectedMMH3    = "13942501"
	)

	finger := &Finger{
		Name:              "nacos",
		Focus:             true,
		Tags:              []string{"nacos"},
		Protocol:          HTTPProtocol,
		DefaultPort:       []string{"80"},
		SendDataStr:       fingerSendPath,
		EnableMatchDetail: true,
		Rules: Rules{
			{
				Regexps: &Regexps{
					Body: []string{"<title>Nacos</title>"},
				},
			},
			{
				Favicon: &Favicons{
					Mmh3: []string{expectedMMH3},
				},
				SendDataStr: faviconSendPath,
				Level:       2,
			},
		},
	}

	if err := finger.Compile(false); err != nil {
		t.Fatalf("failed to compile finger: %v", err)
	}

	client := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	sent := make([]string, 0, 4)
	sender := Sender(func(data []byte) ([]byte, bool) {
		path := string(data)
		sent = append(sent, path)
		req, err := http.NewRequest(http.MethodGet, baseURL+path, nil)
		if err != nil {
			t.Logf("request build error for %s: %v", path, err)
			return nil, false
		}
		req.Header.Set("User-Agent", "fingers-test/nacos-fingerprint")
		resp, err := client.Do(req)
		if err != nil {
			t.Logf("request error for %s: %v", path, err)
			return nil, false
		}
		defer resp.Body.Close()
		return httputils.ReadRaw(resp), true
	})

	frame, _, ok := finger.ActiveMatch(2, sender)
	if !ok || frame == nil {
		t.Fatalf("expected nacos active match to succeed")
	}

	// Validate the favicon hash from the real site.
	req, err := http.NewRequest(http.MethodGet, baseURL+faviconSendPath, nil)
	if err != nil {
		t.Fatalf("failed to build favicon request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Skipf("network error fetching favicon path: %v", err)
		return
	}
	defer resp.Body.Close()
	raw := httputils.ReadRaw(resp)
	body, _, splitOK := httputils.SplitHttpRaw(raw)
	if !splitOK || len(body) == 0 {
		t.Fatalf("failed to split favicon response body")
	}
	if got := encode.Mmh3Hash32(body); got != expectedMMH3 {
		t.Fatalf("unexpected mmh3 for favicon: got %s want %s", got, expectedMMH3)
	}

	t.Logf("sent paths: %v", sent)
	if frame.MatchDetail != nil {
		t.Logf("matcher detail: %+v", *frame.MatchDetail)
	}
}

func TestNacosFingerprint_RealSite_RuleSendDataOnly(t *testing.T) {
	const (
		baseURL         = "https://nacos.lzfzkj.com"
		faviconSendPath = "/nacos/console-ui/public/img/nacos-logo.png"
		expectedMMH3    = "13942501"
	)

	yamlContent := `name: nacos
focus: true
tag:
- nacos
rule:
- regexps:
    body:
    - <title>Nacos</title>
- favicon:
    mmh3:
      - "` + expectedMMH3 + `"
  send_data: ` + faviconSendPath + `
`

	var parsed Fingers
	if err := yaml.Unmarshal([]byte(yamlContent), &parsed); err != nil {
		var single Finger
		if errSingle := yaml.Unmarshal([]byte(yamlContent), &single); errSingle != nil {
			t.Fatalf("failed to parse yaml: %v", err)
		}
		parsed = Fingers{&single}
	}
	if len(parsed) == 0 || parsed[0] == nil {
		t.Fatalf("no fingerprint parsed from yaml")
	}
	finger := parsed[0]
	finger.EnableMatchDetail = true
	if err := finger.Compile(false); err != nil {
		t.Fatalf("failed to compile finger: %v", err)
	}

	client := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	sent := make([]string, 0, 4)
	sender := Sender(func(data []byte) ([]byte, bool) {
		path := string(data)
		sent = append(sent, path)
		req, err := http.NewRequest(http.MethodGet, baseURL+path, nil)
		if err != nil {
			t.Logf("request build error for %s: %v", path, err)
			return nil, false
		}
		req.Header.Set("User-Agent", "fingers-test/nacos-fingerprint")
		resp, err := client.Do(req)
		if err != nil {
			t.Logf("request error for %s: %v", path, err)
			return nil, false
		}
		defer resp.Body.Close()
		return httputils.ReadRaw(resp), true
	})

	frame, _, ok := finger.ActiveMatch(2, sender)
	if !ok || frame == nil {
		t.Fatalf("expected nacos active match to succeed")
	}

	if len(sent) == 0 {
		t.Fatalf("expected at least one send_data to be sent")
	}

	t.Logf("sent paths: %v", sent)
	if frame.MatchDetail != nil {
		t.Logf("matcher detail: %+v", *frame.MatchDetail)
	}
}
