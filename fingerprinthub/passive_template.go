package fingerprinthub

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"

	"github.com/chainreactors/neutron/operators"
	"github.com/chainreactors/neutron/protocols"
	"github.com/chainreactors/utils/encode"
	"gopkg.in/yaml.v3"
)

type passiveTemplate struct {
	id       string
	name     string
	metadata map[string]interface{}
	requests []*passiveRequest
}

type passiveRequest struct {
	Matchers          []*operators.Matcher   `yaml:"matchers"`
	MatchersCondition string                 `yaml:"matchers-condition"`
	Extractors        []*operators.Extractor `yaml:"extractors"`
	compiledOperators *operators.Operators
}

func parsePassiveTemplate(raw map[string]interface{}) (*passiveTemplate, error) {
	pt := &passiveTemplate{}

	if id, ok := raw["id"].(string); ok {
		pt.id = id
	}

	if info, ok := raw["info"].(map[string]interface{}); ok {
		if name, ok := info["name"].(string); ok {
			pt.name = name
		}
		if meta, ok := info["metadata"].(map[string]interface{}); ok {
			pt.metadata = meta
		}
	}

	httpReqs, _ := raw["http"].([]interface{})
	if httpReqs == nil {
		httpReqs, _ = raw["requests"].([]interface{})
	}

	for _, reqRaw := range httpReqs {
		reqMap, ok := reqRaw.(map[string]interface{})
		if !ok {
			continue
		}

		yamlBytes, err := yaml.Marshal(reqMap)
		if err != nil {
			continue
		}

		pr := &passiveRequest{}
		if err := yaml.Unmarshal(yamlBytes, pr); err != nil {
			continue
		}

		ops := &operators.Operators{
			Matchers:          pr.Matchers,
			MatchersCondition: pr.MatchersCondition,
			Extractors:        pr.Extractors,
		}
		if err := ops.Compile(); err != nil {
			return nil, fmt.Errorf("compile operators for %s: %w", pt.id, err)
		}
		pr.compiledOperators = ops
		pt.requests = append(pt.requests, pr)
	}

	return pt, nil
}

func parseRawHTTPEvent(content []byte, caseInsensitive bool) (protocols.InternalEvent, bool) {
	idx := bytes.Index(content, []byte("\r\n\r\n"))
	if idx < 0 {
		idx = bytes.Index(content, []byte("\n\n"))
		if idx < 0 {
			return nil, false
		}
	}

	headerSection := content[:idx]
	body := content[idx:]
	if bytes.HasPrefix(body, []byte("\r\n\r\n")) {
		body = body[4:]
	} else if bytes.HasPrefix(body, []byte("\n\n")) {
		body = body[2:]
	}

	lines := bytes.Split(headerSection, []byte("\n"))
	if len(lines) == 0 {
		return nil, false
	}

	// Parse status line
	firstLine := string(bytes.TrimRight(lines[0], "\r"))
	statusCode := 0
	if parts := strings.SplitN(firstLine, " ", 3); len(parts) >= 2 {
		statusCode, _ = strconv.Atoi(parts[1])
	}

	// Parse headers
	var headerBuilder strings.Builder
	for _, line := range lines[1:] {
		lineStr := string(bytes.TrimRight(line, "\r"))
		if lineStr == "" {
			continue
		}
		colonIdx := strings.IndexByte(lineStr, ':')
		if colonIdx < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(lineStr[:colonIdx]))
		value := strings.TrimSpace(lineStr[colonIdx+1:])
		if caseInsensitive {
			value = strings.ToLower(value)
		}
		headerBuilder.WriteString(key)
		headerBuilder.WriteString(": ")
		headerBuilder.WriteString(value)
		headerBuilder.WriteString("\n")
	}

	bodyStr := string(body)
	if caseInsensitive {
		bodyStr = strings.ToLower(bodyStr)
	}

	event := make(protocols.InternalEvent)
	event["body"] = bodyStr
	event["status_code"] = statusCode
	event["content_length"] = len(content)
	event["all_headers"] = headerBuilder.String()
	event["header"] = headerBuilder.String()
	event["favicon_hash"] = encode.Mmh3Hash32(body)

	return event, true
}

func matchPassiveRequest(req *passiveRequest, event protocols.InternalEvent) bool {
	if len(req.Matchers) == 0 {
		return false
	}

	matchersCondition := req.MatchersCondition
	if matchersCondition == "" {
		matchersCondition = "or"
	}

	matchedCount := 0
	for _, matcher := range req.Matchers {
		matched, _ := protocols.HTTPMatch(event, matcher)
		if matched {
			matchedCount++
			if matchersCondition == "or" {
				return true
			}
		} else {
			if matchersCondition == "and" {
				return false
			}
		}
	}

	if matchersCondition == "and" {
		return matchedCount == len(req.Matchers)
	}

	return false
}
