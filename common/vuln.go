package common

import (
	"fmt"
	"github.com/chainreactors/utils/iutils"
	"strings"
)

const (
	SeverityINFO int = iota + 1
	SeverityMEDIUM
	SeverityHIGH
	SeverityCRITICAL
	SeverityUnknown
)

func GetSeverityLevel(s string) int {
	switch s {
	case "info":
		return SeverityINFO
	case "medium":
		return SeverityMEDIUM
	case "high":
		return SeverityHIGH
	case "critical":
		return SeverityCRITICAL
	default:
		return SeverityUnknown
	}
}

var SeverityMap = map[int]string{
	SeverityINFO:     "info",
	SeverityMEDIUM:   "medium",
	SeverityHIGH:     "high",
	SeverityCRITICAL: "critical",
}

type Vuln struct {
	Name          string                 `json:"name"`
	Tags          []string               `json:"tags,omitempty"`
	Payload       map[string]interface{} `json:"payload,omitempty"`
	Detail        map[string][]string    `json:"detail,omitempty"`
	SeverityLevel int                    `json:"severity"`
}

func (v *Vuln) GetPayload() string {
	return iutils.MapToString(v.Payload)
}

func (v *Vuln) GetDetail() string {
	var s strings.Builder
	for k, v := range v.Detail {
		s.WriteString(fmt.Sprintf(" %s:%s ", k, strings.Join(v, ",")))
	}
	return s.String()
}

func (v *Vuln) String() string {
	s := v.Name
	if payload := v.GetPayload(); payload != "" {
		s += fmt.Sprintf(" payloads:%s", payload)
	}
	if detail := v.GetDetail(); detail != "" {
		s += fmt.Sprintf(" payloads:%s", detail)
	}
	return s
}

type Vulns map[string]*Vuln

func (fs Vulns) Add(other *Vuln) {
	fs[other.Name] = other
}

func (vs Vulns) String() string {
	var s string

	for _, vuln := range vs {
		s += fmt.Sprintf("[ %s: %s ] ", SeverityMap[vuln.SeverityLevel], vuln.String())
	}
	return s
}
