package fingerprinthub

import (
	"encoding/json"
	"github.com/chainreactors/fingers/common"
	"github.com/chainreactors/fingers/resources"
	"net/http"
	"strings"
)

func NewFingerPrintHubEngine() (*FingerPrintHubsEngine, error) {
	var fingerprints []*FingerPrintHub
	err := json.Unmarshal(resources.Fingerprinthubdata, &fingerprints)
	if err != nil {
		return nil, err
	}
	engine := &FingerPrintHubsEngine{FingerPrints: fingerprints}
	err = engine.Compile()
	if err != nil {
		return nil, err
	}
	return engine, nil
}

type FingerPrintHubsEngine struct {
	FingerPrints []*FingerPrintHub `json:"fingerprints"`
	FaviconMap   map[string]string `json:"favicon_map,omitempty"`
}

func (f *FingerPrintHubsEngine) Compile() error {
	f.FaviconMap = make(map[string]string)
	for _, finger := range f.FingerPrints {
		if len(finger.FaviconHash) > 0 {
			for _, hash := range finger.FaviconHash {
				f.FaviconMap[hash] = finger.Name
			}
		}
	}
	return nil
}

func (f *FingerPrintHubsEngine) Match(header http.Header, body string) common.Frameworks {
	frames := make(common.Frameworks)
	for _, finger := range f.FingerPrints {
		frame := finger.Match(header, body)
		if frame != nil {
			frames.Add(frame)
		}
	}
	return frames
}

type FingerPrintHub struct {
	Name        string            `json:"name"`
	FaviconHash []string          `json:"favicon_hash,omitempty"`
	Keyword     []string          `json:"keyword,omitempty"`
	Path        string            `json:"path"`
	Headers     map[string]string `json:"headers,omitempty"`
}

func (f *FingerPrintHub) Match(header http.Header, body string) *common.Framework {
	if len(f.Keyword) == 0 && len(f.Headers) == 0 {
		return nil
	}
	status := false
	if f.MatchHeader(header) && f.MatchBody(body) { // fingerprinthub 指纹库规则为且
		status = true
	}

	if status {
		return common.NewFramework(f.Name, common.FrameFromFingerprintHub)
	}
	return nil
}

func (f *FingerPrintHub) MatchHeader(header http.Header) bool {
	if len(f.Headers) == 0 {
		return true
	}
	status := true
	for k, v := range f.Headers {
		if v == "*" && header.Get(k) != "" {
			status = true
		} else if h := header.Get(k); h != "" && strings.Contains(h, v) {
			status = true
		} else {
			return false
		}
	}
	return status
}

func (f *FingerPrintHub) MatchBody(body string) bool {
	if len(f.Keyword) == 0 {
		return true
	}
	if body == "" {
		return false
	}
	status := true
	for _, key := range f.Keyword {
		if strings.Contains(body, key) {
			status = true
		} else {
			return false
		}
	}
	return status
}
