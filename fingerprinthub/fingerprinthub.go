package fingerprinthub

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/chainreactors/fingers/common"
	"github.com/chainreactors/fingers/resources"
	"github.com/chainreactors/logs"
	"gopkg.in/yaml.v3"
)

// activeLoader is set by active.go's init() to load full templates
// for HTTPActiveMatch and ServiceMatch. Nil in passive_only builds.
var activeLoader func(engine *FingerPrintHubEngine, webRaw, serviceRaw []map[string]interface{})

// FingerPrintHubEngine provides fingerprint matching using neutron-style templates.
type FingerPrintHubEngine struct {
	webTemplates     []*passiveTemplate
	webTemplateIndex *TemplateKeywordIndex

	// CaseInsensitive controls whether matching ignores case (default true).
	CaseInsensitive bool

	// active holds full neutron templates for HTTPActiveMatch/ServiceMatch.
	// Nil in passive_only builds.
	active *activeState
}

// NewFingerPrintHubEngine creates a new engine instance.
func NewFingerPrintHubEngine(webData, serviceData []byte) (*FingerPrintHubEngine, error) {
	engine := &FingerPrintHubEngine{
		CaseInsensitive: true,
	}

	var webRaw []map[string]interface{}
	if err := resources.UnmarshalData(webData, &webRaw); err != nil {
		return nil, fmt.Errorf("failed to unmarshal web fingerprints: %w", err)
	}

	var serviceRaw []map[string]interface{}
	if err := resources.UnmarshalData(serviceData, &serviceRaw); err != nil {
		return nil, fmt.Errorf("failed to unmarshal service fingerprints: %w", err)
	}

	webCount, webErrors := engine.loadPassiveTemplates(webRaw)

	if len(webErrors) > 0 && len(webErrors) < 10 {
		for _, e := range webErrors {
			logs.Log.Warn(e)
		}
	}

	// Load active templates if the active build is linked
	if activeLoader != nil {
		activeLoader(engine, webRaw, serviceRaw)
	}

	logs.Log.Infof("resources type=fingerprints source=fingerprinthub web=%d", webCount)

	engine.webTemplateIndex = NewTemplateKeywordIndex(engine.webTemplates)

	return engine, nil
}

func (engine *FingerPrintHubEngine) loadPassiveTemplates(templateData []map[string]interface{}) (int, []error) {
	loadedCount := 0
	var errors []error

	for _, raw := range templateData {
		sanitizeTemplateForTinyGo(raw)

		pt, err := parsePassiveTemplate(raw)
		if err != nil {
			errors = append(errors, err)
			continue
		}
		if len(pt.requests) == 0 {
			continue
		}

		if engine.CaseInsensitive {
			for _, req := range pt.requests {
				for _, matcher := range req.Matchers {
					if matcher.Type == "word" {
						matcher.CaseInsensitive = true
					}
				}
				if req.compiledOperators != nil {
					req.compiledOperators.Compile()
				}
			}
		}

		engine.webTemplates = append(engine.webTemplates, pt)
		loadedCount++
	}

	return loadedCount, errors
}

// LoadFromJSON loads fingerprints from JSON data.
func (engine *FingerPrintHubEngine) LoadFromJSON(data []byte) error {
	var templateData []map[string]interface{}
	if err := json.Unmarshal(data, &templateData); err != nil {
		return fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	loadedCount := 0
	var errors []error

	for _, raw := range templateData {
		sanitizeTemplateForTinyGo(raw)

		pt, err := parsePassiveTemplate(raw)
		if err != nil {
			errors = append(errors, err)
			continue
		}
		if len(pt.requests) == 0 {
			continue
		}

		if engine.CaseInsensitive {
			for _, req := range pt.requests {
				for _, matcher := range req.Matchers {
					if matcher.Type == "word" {
						matcher.CaseInsensitive = true
					}
				}
				if req.compiledOperators != nil {
					req.compiledOperators.Compile()
				}
			}
		}

		engine.webTemplates = append(engine.webTemplates, pt)
		loadedCount++
	}

	if len(errors) > 0 && len(errors) < 10 {
		for _, e := range errors {
			logs.Log.Warn(e)
		}
	}
	_ = loadedCount

	return nil
}

// Name returns the engine name.
func (engine *FingerPrintHubEngine) Name() string {
	return "fingerprinthub"
}

// Len returns the number of fingerprints.
func (engine *FingerPrintHubEngine) Len() int {
	n := len(engine.webTemplates)
	if engine.active != nil {
		// active.go exposes activeLen()
		n += activeServiceLen(engine)
	}
	return n
}

// Compile is a no-op — templates are compiled during loading.
func (engine *FingerPrintHubEngine) Compile() error {
	return nil
}

// Capability returns the engine's capabilities.
func (engine *FingerPrintHubEngine) Capability() common.EngineCapability {
	return common.EngineCapability{
		SupportWeb:     true,
		SupportService: engine.active != nil,
	}
}

// WebMatch performs passive web fingerprint matching against raw HTTP content.
func (engine *FingerPrintHubEngine) WebMatch(content []byte) common.Frameworks {
	event, ok := parseRawHTTPEvent(content, engine.CaseInsensitive)
	if !ok {
		return make(common.Frameworks)
	}

	frames := make(common.Frameworks)

	bodyStr, _ := event["body"].(string)
	headerStr, _ := event["all_headers"].(string)
	lowerBodyStr := bodyStr
	lowerHeaderStr := headerStr
	if !engine.CaseInsensitive {
		lowerBodyStr = strings.ToLower(bodyStr)
		lowerHeaderStr = strings.ToLower(headerStr)
	}

	mr := engine.webTemplateIndex.Match(lowerHeaderStr, lowerBodyStr)

	if engine.CaseInsensitive {
		for ti := range mr.Matched {
			frames.Add(engine.newFramework(engine.webTemplates[ti]))
		}
	}

	if !engine.CaseInsensitive {
		for ti := range mr.Matched {
			mr.NeedsCheck[ti] = true
		}
	}
	for ti := range mr.NeedsCheck {
		tmpl := engine.webTemplates[ti]
		if len(tmpl.requests) == 0 {
			continue
		}

		for _, req := range tmpl.requests {
			if len(req.Matchers) == 0 {
				continue
			}
			if matchPassiveRequest(req, event) {
				frames.Add(engine.newFramework(tmpl))
				break
			}
		}
	}

	return frames
}

func (engine *FingerPrintHubEngine) newFramework(tmpl *passiveTemplate) *common.Framework {
	name := tmpl.name
	if name == "" {
		name = tmpl.id
	}
	frame := common.NewFramework(name, common.FrameFromFingerprintHub)
	if tmpl.metadata != nil {
		if vendor, ok := tmpl.metadata["vendor"].(string); ok {
			frame.Attributes.Vendor = vendor
		}
		if product, ok := tmpl.metadata["product"].(string); ok {
			frame.Attributes.Product = product
		}
	}
	return frame
}

// ─── Helpers shared between passive and active builds ───

// activeServiceLen returns the number of service templates in active state.
// Called from Len() — safe to call when engine.active is nil.
func activeServiceLen(engine *FingerPrintHubEngine) int {
	_ = engine
	return 0 // overridden by active.go via init or linker
}

// yamlMarshal is a convenience wrapper.
func yamlMarshal(v interface{}) ([]byte, error) {
	return yaml.Marshal(v)
}
