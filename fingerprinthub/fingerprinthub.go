package fingerprinthub

import (
	"encoding/json"
	"github.com/chainreactors/fingers/common"
	"net/http"
	"strings"
)

var fingerprinthubdata []byte

type FingerPrintHub struct {
	Name        string            `json:"name"`
	FaviconHash []string          `json:"favicon_hash,omitempty"`
	Keyword     []string          `json:"keyword,omitempty"`
	Path        string            `json:"path"`
	Headers     map[string]string `json:"headers,omitempty"`
}

func (f *FingerPrintHub) Match(header http.Header, body string) *common.Framework {
	status := false
	if f.MatchHeader(header) && f.MatchBody(body) { // fingerprinthub 指纹库规则为且
		status = true
	}

	if status {
		return &common.Framework{
			Name: f.Name,
			From: common.FrameFromDefault,
			Tags: []string{"fingerprinthub"},
		}
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

type FingerPrintHubs []*FingerPrintHub

func (f FingerPrintHubs) Match(header http.Header, body string) common.Frameworks {
	frames := make(common.Frameworks)
	for _, finger := range f {
		frame := finger.Match(header, body)
		if frame != nil {
			frames.Add(frame)
		}
	}
	return frames
}

func NewFingerPrintHubEngine() (*FingerPrintHubs, error) {
	var engine *FingerPrintHubs
	err := json.Unmarshal(fingerprinthubdata, &engine)
	if err != nil {
		return nil, err
	}
	return engine, nil
}
