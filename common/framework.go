package common

import (
	"github.com/chainreactors/utils/parsers"
)

type FingerprintType int

const (
	WebFingerprint     FingerprintType = iota
	ServiceFingerprint
)

type EngineCapability struct {
	SupportWeb     bool
	SupportService bool
}

type ServiceResult struct {
	Framework *Framework
	Vuln      *Vuln
}

// Re-export types from parsers for backward compatibility.
type From = parsers.From
type Framework = parsers.Framework
type MatchDetail = parsers.MatchDetail
type Frameworks = parsers.Frameworks
type Attributes = parsers.Attributes

var FrameFromMap = parsers.FrameFromMap

const (
	FrameFromDefault        = parsers.FrameFromDefault
	FrameFromACTIVE         = parsers.FrameFromACTIVE
	FrameFromICO            = parsers.FrameFromICO
	FrameFromNOTFOUND       = parsers.FrameFromNOTFOUND
	FrameFromGUESS          = parsers.FrameFromGUESS
	FrameFromRedirect       = parsers.FrameFromRedirect
	FrameFromFingers        = parsers.FrameFromFingers
	FrameFromFingerprintHub = parsers.FrameFromFingerprintHub
	FrameFromWappalyzer     = parsers.FrameFromWappalyzer
	FrameFromEhole          = parsers.FrameFromEhole
	FrameFromGoby           = parsers.FrameFromGoby
	FrameFromNmap           = parsers.FrameFromNmap
)

var (
	NewFramework            = parsers.NewFramework
	NewFrameworkWithVersion = parsers.NewFrameworkWithVersion
	GetFrameFrom            = parsers.GetFrameFrom
	NewAttributesWithAny    = parsers.NewAttributesWithAny
	NewAttributesWithCPE    = parsers.NewAttributesWithCPE
	ParseCPEKey             = parsers.ParseCPEKey
	CPEKey                  = parsers.CPEKey
)
