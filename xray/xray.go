// Package xray implements a fingerprint engine based on converted xray POCs.
//
// Unlike fingerprinthub which matches all templates against one response,
// the xray engine matches each template's request independently:
//   - WebMatch (passive): only matches requests targeting path "/"
//   - HTTPActiveMatch (active): sends each request to its specified path,
//     caching responses by path to avoid duplicate requests
package xray

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"

	"github.com/chainreactors/fingers/common"
	"github.com/chainreactors/fingers/resources"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/neutron/operators"
	"github.com/chainreactors/neutron/protocols"
	nhttp "github.com/chainreactors/neutron/protocols/http"
	"github.com/chainreactors/neutron/templates"
	"github.com/chainreactors/utils/httputils"
	"gopkg.in/yaml.v3"
)

const FrameFromXray common.From = common.From(20)

func init() {
	common.FrameFromMap[FrameFromXray] = "xray"
}

// XrayEngine implements fingerprint matching using converted xray POC templates.
type XrayEngine struct {
	templates       []*templates.Template
	executerOptions *protocols.ExecuterOptions

	// CaseInsensitive 控制匹配时是否忽略大小写（默认 true）。
	CaseInsensitive bool
}

// NewXrayEngine creates a new xray fingerprint engine from gzipped JSON data.
func NewXrayEngine(webData []byte) (*XrayEngine, error) {
	engine := &XrayEngine{
		CaseInsensitive: true,
		executerOptions: &protocols.ExecuterOptions{
			Options: &protocols.Options{Timeout: 10},
		},
	}

	// xray data is not embedded; an empty engine is valid (templates are
	// supplied later via the Provider layer).
	if len(webData) == 0 {
		return engine, nil
	}

	var rawTemplates []map[string]interface{}
	if err := resources.UnmarshalData(webData, &rawTemplates); err != nil {
		return nil, fmt.Errorf("unmarshal xray fingerprints: %w", err)
	}

	loaded, errs := engine.loadTemplates(rawTemplates)
	if len(errs) > 0 && len(errs) < 10 {
		for _, e := range errs {
			logs.Log.Warn(e)
		}
	}

	logs.Log.Infof("resources type=fingerprints source=xray templates=%d", loaded)
	return engine, nil
}

func (e *XrayEngine) loadTemplates(data []map[string]interface{}) (int, []error) {
	var loaded int
	var errs []error

	for _, raw := range data {
		yb, err := yaml.Marshal(raw)
		if err != nil {
			errs = append(errs, fmt.Errorf("marshal: %w", err))
			continue
		}
		tmpl := &templates.Template{}
		if err := yaml.Unmarshal(yb, tmpl); err != nil {
			errs = append(errs, fmt.Errorf("unmarshal: %w", err))
			continue
		}
		if err := e.compileTemplate(tmpl); err != nil {
			for _, req := range tmpl.GetRequests() {
				if compileErr := (&req.Operators).Compile(); compileErr != nil {
					continue
				}
				req.CompiledOperators = &req.Operators
			}
		}
		if tmpl.GetRequests() != nil {
			e.templates = append(e.templates, tmpl)
			loaded++
		}
	}
	return loaded, errs
}

func (e *XrayEngine) compileTemplate(tmpl *templates.Template) error {
	if e.CaseInsensitive {
		for _, req := range tmpl.GetRequests() {
			for _, matcher := range req.Matchers {
				if matcher.Type == "word" {
					matcher.CaseInsensitive = true
				}
			}
		}
	}
	return tmpl.Compile(e.executerOptions)
}

// ---------------------------------------------------------------------------
// EngineImpl interface
// ---------------------------------------------------------------------------

func (e *XrayEngine) Name() string                            { return "xray" }
func (e *XrayEngine) Len() int                                { return len(e.templates) }
func (e *XrayEngine) Compile() error                          { return nil }
func (e *XrayEngine) Capability() common.EngineCapability {
	return common.EngineCapability{SupportWeb: true, SupportService: false}
}

// WebMatch performs passive fingerprint matching against an HTTP response.
// Only requests targeting path "/" are matched (other paths require active probing).
func (e *XrayEngine) WebMatch(content []byte) common.Frameworks {
	resp := httputils.NewResponseWithRaw(content)
	if resp == nil {
		return make(common.Frameworks)
	}

	bodyStr := string(httputils.ReadBody(resp))
	if e.CaseInsensitive {
		bodyStr = strings.ToLower(bodyStr)
	}
	event := e.buildEvent(resp, bodyStr, len(content))
	frames := make(common.Frameworks)

	for _, tmpl := range e.templates {
		if e.matchTemplatePassive(tmpl, event) {
			frames.Add(e.newFramework(tmpl))
		}
	}
	return frames
}

// matchTemplatePassive checks if ANY root-path request in the template matches.
// Only requests with path "/" or "{{BaseURL}}/" are evaluated in passive mode.
func (e *XrayEngine) matchTemplatePassive(tmpl *templates.Template, event protocols.InternalEvent) bool {
	for _, req := range tmpl.GetRequests() {
		if !isRootPath(req) {
			continue
		}
		if req.CompiledOperators == nil || len(req.CompiledOperators.Matchers) == 0 {
			continue
		}
		if matchRequest(req, event) {
			return true
		}
	}
	return false
}

func isRootPath(req *nhttp.Request) bool {
	if len(req.Path) == 0 {
		return true
	}
	for _, p := range req.Path {
		cleaned := strings.TrimPrefix(p, "{{BaseURL}}")
		cleaned = strings.TrimSuffix(cleaned, "/")
		if cleaned == "" || cleaned == "/" {
			return true
		}
	}
	return false
}

func matchRequest(req *nhttp.Request, event protocols.InternalEvent) bool {
	cond := strings.ToLower(strings.TrimSpace(req.CompiledOperators.MatchersCondition))
	if cond == "" {
		cond = "or"
	}

	anyMatched, allMatched := false, true
	for _, matcher := range req.CompiledOperators.Matchers {
		ok, _ := req.Match(event, matcher)
		if ok {
			anyMatched = true
		} else {
			allMatched = false
		}
	}
	if cond == "and" {
		return allMatched && len(req.CompiledOperators.Matchers) > 0
	}
	return anyMatched
}

func (e *XrayEngine) buildEvent(resp *http.Response, body string, contentLength int) protocols.InternalEvent {
	event := make(protocols.InternalEvent)
	event["body"] = body
	event["status_code"] = resp.StatusCode
	event["content_length"] = contentLength

	var hdrBuilder strings.Builder
	for k, vals := range resp.Header {
		joined := strings.Join(vals, " ")
		norm := strings.ToLower(strings.Replace(strings.TrimSpace(k), "-", "_", -1))
		if e.CaseInsensitive {
			joined = strings.ToLower(joined)
		}
		event[norm] = joined
		hdrBuilder.WriteString(norm)
		hdrBuilder.WriteString(": ")
		hdrBuilder.WriteString(joined)
		hdrBuilder.WriteString("\n")
	}
	event["all_headers"] = hdrBuilder.String()
	event["header"] = hdrBuilder.String()
	return event
}

func (e *XrayEngine) newFramework(tmpl *templates.Template) *common.Framework {
	name := tmpl.Info.Name
	if name == "" {
		name = tmpl.Id
	}
	frame := common.NewFramework(name, FrameFromXray)
	if tmpl.Info.Metadata != nil {
		if vendor, ok := tmpl.Info.Metadata["vendor"].(string); ok {
			frame.Attributes.Vendor = vendor
		}
		if product, ok := tmpl.Info.Metadata["product"].(string); ok {
			frame.Attributes.Product = product
		}
	}
	return frame
}

// ServiceMatch is not supported by the xray engine.
func (e *XrayEngine) ServiceMatch(host, portStr string, level int, sender common.ServiceSender, callback common.ServiceCallback) *common.ServiceResult {
	return nil
}

// ---------------------------------------------------------------------------
// Active matching with per-request dispatch and path-level caching
// ---------------------------------------------------------------------------

// cachedTransport caches HTTP responses by request path to avoid duplicate requests.
type cachedTransport struct {
	transport http.RoundTripper
	cache     map[string]*cachedResp
	mu        sync.Mutex
}

type cachedResp struct {
	resp *http.Response
	body []byte
}

func (c *cachedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	key := req.URL.Path
	if key == "" {
		key = "/"
	}

	c.mu.Lock()
	if cached, ok := c.cache[key]; ok {
		c.mu.Unlock()
		resp := *cached.resp
		resp.Body = ioutil.NopCloser(bytes.NewReader(cached.body))
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

	cr := *resp
	cr.Body = nil
	c.mu.Lock()
	c.cache[key] = &cachedResp{resp: &cr, body: bodyBytes}
	c.mu.Unlock()

	resp.Body = ioutil.NopCloser(bytes.NewReader(bodyBytes))
	return resp, nil
}

// HTTPActiveMatch sends per-template per-request probes with path-level caching.
func (e *XrayEngine) HTTPActiveMatch(baseURL string, level int, transport http.RoundTripper, callback func(*common.Framework, *common.Vuln)) (common.Frameworks, common.Vulns) {
	if baseURL == "" || transport == nil {
		return nil, nil
	}

	allFrameworks := make(common.Frameworks)
	ct := &cachedTransport{transport: transport, cache: make(map[string]*cachedResp)}
	client := &http.Client{Transport: ct}
	for _, tmpl := range e.templates {
		if len(tmpl.RequestsHTTP) == 0 {
			continue
		}

		origClients := make([]*http.Client, len(tmpl.RequestsHTTP))
		for i, req := range tmpl.RequestsHTTP {
			origClients[i] = req.GetHTTPClient()
			req.SetHTTPClient(client)
		}

		result, err := tmpl.Execute(baseURL, nil)
		if err == nil && result != nil && result.Matched {
			frame := e.newFramework(tmpl)
			allFrameworks.Add(frame)
			if callback != nil {
				callback(frame, nil)
			}
		}

		for i, req := range tmpl.RequestsHTTP {
			req.SetHTTPClient(origClients[i])
		}
	}
	return allFrameworks, nil
}

// LoadFromJSON loads templates from a raw JSON byte slice (for testing).
func (e *XrayEngine) LoadFromJSON(data []byte) error {
	var raw []map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	loaded, _ := e.loadTemplates(raw)
	_ = loaded
	return nil
}

// GetTemplateMatchersForRequest returns the set of matchers for a template,
// for a specific request (by index).
func GetTemplateMatchersForRequest(tmpl *templates.Template, reqIndex int) []*operators.Matcher {
	reqs := tmpl.GetRequests()
	if reqIndex < 0 || reqIndex >= len(reqs) {
		return nil
	}
	req := reqs[reqIndex]
	if req.CompiledOperators == nil {
		return nil
	}
	return req.CompiledOperators.Matchers
}
