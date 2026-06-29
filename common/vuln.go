package common

import (
	"github.com/chainreactors/utils/parsers"
)

// Re-export types from parsers for backward compatibility.
type Vuln = parsers.Vuln
type Vulns = parsers.Vulns

// Re-export severity constants and helpers.
const (
	SeverityINFO     = parsers.SeverityINFO
	SeverityMEDIUM   = parsers.SeverityMEDIUM
	SeverityHIGH     = parsers.SeverityHIGH
	SeverityCRITICAL = parsers.SeverityCRITICAL
	SeverityUnknown  = parsers.SeverityUnknown
)

var (
	SeverityMap      = parsers.SeverityMap
	GetSeverityLevel = parsers.GetSeverityLevel
)
