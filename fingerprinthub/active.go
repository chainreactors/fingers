//go:build !passive_only
// +build !passive_only

package fingerprinthub

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"

	"github.com/chainreactors/fingers/common"
	"github.com/chainreactors/neutron/protocols"
	"github.com/chainreactors/neutron/templates"
	"gopkg.in/yaml.v3"
)

type activeState struct {
	webTemplates     []*templates.Template
	serviceTemplates []*templates.Template
	executerOptions  *protocols.ExecuterOptions
}

func init() {
	activeLoader = func(engine *FingerPrintHubEngine, webRaw, serviceRaw []map[string]interface{}) {
		engine.active = &activeState{
			executerOptions: &protocols.ExecuterOptions{
				Options: &protocols.Options{Timeout: 10},
			},
		}

		for _, raw := range webRaw {
			sanitizeTemplateForTinyGo(raw)
			yamlBytes, err := yaml.Marshal(raw)
			if err != nil {
				continue
			}
			tmpl := &templates.Template{}
			if err := yaml.Unmarshal(yamlBytes, tmpl); err != nil {
				continue
			}
			if engine.CaseInsensitive {
				for _, req := range tmpl.GetRequests() {
					for _, matcher := range req.Matchers {
						if matcher.Type == "word" {
							matcher.CaseInsensitive = true
						}
					}
				}
			}
			if err := tmpl.Compile(engine.active.executerOptions); err != nil {
				continue
			}
			engine.active.webTemplates = append(engine.active.webTemplates, tmpl)
		}

		for _, raw := range serviceRaw {
			sanitizeTemplateForTinyGo(raw)
			yamlBytes, err := yaml.Marshal(raw)
			if err != nil {
				continue
			}
			tmpl := &templates.Template{}
			if err := yaml.Unmarshal(yamlBytes, tmpl); err != nil {
				continue
			}
			if err := tmpl.Compile(engine.active.executerOptions); err != nil {
				continue
			}
			for _, netReq := range tmpl.RequestsNetwork {
				for _, input := range netReq.Inputs {
					if input.Read == 0 {
						input.Read = 1024
					}
				}
				if netReq.ReadSize == 0 {
					netReq.ReadSize = 1024
				}
			}
			engine.active.serviceTemplates = append(engine.active.serviceTemplates, tmpl)
		}
	}
}

// CachedResponse stores a cached HTTP response.
type CachedResponse struct {
	Response *http.Response
	Body     []byte
}

// CachedTransport implements http.RoundTripper with path-based caching.
type CachedTransport struct {
	transport http.RoundTripper
	cache     map[string]*CachedResponse
	mu        sync.Mutex
}

func (c *CachedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	cacheKey := req.URL.Path
	if cacheKey == "" {
		cacheKey = "/"
	}

	c.mu.Lock()
	if cached, ok := c.cache[cacheKey]; ok {
		c.mu.Unlock()
		resp := *cached.Response
		resp.Body = ioutil.NopCloser(bytes.NewReader(cached.Body))
		resp.Request = req
		return &resp, nil
	}
	c.mu.Unlock()

	resp, err := c.transport.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}

	cachedResp := *resp
	cachedResp.Body = nil
	c.mu.Lock()
	c.cache[cacheKey] = &CachedResponse{Response: &cachedResp, Body: bodyBytes}
	c.mu.Unlock()

	resp.Body = ioutil.NopCloser(bytes.NewReader(bodyBytes))
	return resp, nil
}

// HTTPActiveMatch performs active HTTP fingerprinting using a provided transport.
func (engine *FingerPrintHubEngine) HTTPActiveMatch(baseURL string, level int, transport http.RoundTripper, callback func(*common.Framework, *common.Vuln)) (common.Frameworks, common.Vulns) {
	if baseURL == "" || transport == nil || engine.active == nil {
		return nil, nil
	}

	allFrameworks := make(common.Frameworks)
	allVulns := make(common.Vulns)

	cachedTransport := &CachedTransport{
		transport: transport,
		cache:     make(map[string]*CachedResponse),
	}

	for _, tmpl := range engine.active.webTemplates {
		if len(tmpl.RequestsHTTP) == 0 {
			continue
		}
		result, err := tmpl.ExecuteWithTransport(baseURL, nil, cachedTransport)
		if err == nil && result != nil && result.Matched {
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
			allFrameworks.Add(frame)
			if callback != nil {
				callback(frame, nil)
			}
		}
	}

	return allFrameworks, allVulns
}

// ServiceMatch performs service fingerprinting via network probes.
func (engine *FingerPrintHubEngine) ServiceMatch(host string, portStr string, level int, sender common.ServiceSender, callback common.ServiceCallback) *common.ServiceResult {
	if engine.active == nil {
		return nil
	}

	target := fmt.Sprintf("%s:%s", host, portStr)
	scanCtx := &protocols.ScanContext{Input: target}

	for _, tmpl := range engine.active.serviceTemplates {
		if len(tmpl.RequestsNetwork) == 0 {
			continue
		}
		for _, networkReq := range tmpl.RequestsNetwork {
			var matched bool
			networkReq.ExecuteWithResults(scanCtx, make(map[string]interface{}), make(map[string]interface{}), func(event *protocols.InternalWrappedEvent) {
				if event.OperatorsResult != nil {
					if event.OperatorsResult.Matched || len(event.OperatorsResult.OutputExtracts()) > 0 {
						matched = true
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
						if callback != nil {
							callback(&common.ServiceResult{Framework: frame})
						}
					}
				}
			})
			_ = matched
		}
	}

	return nil
}
