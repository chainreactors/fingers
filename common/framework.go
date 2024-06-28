package common

import (
	"github.com/chainreactors/utils/iutils"
	"github.com/facebookincubator/nvdtools/wfn"
	"strings"
)

const (
	FrameFromDefault = iota
	FrameFromACTIVE
	FrameFromICO
	FrameFromNOTFOUND
	FrameFromGUESS
	FrameFromRedirect
	FrameFromFingerprintHub
	FrameFromWappalyzer
	FrameFromEhole
	FrameFromGoby
)

var NoGuess bool
var frameFromMap = map[int]string{
	FrameFromDefault:        "finger",
	FrameFromACTIVE:         "active",
	FrameFromICO:            "ico",
	FrameFromNOTFOUND:       "404",
	FrameFromGUESS:          "guess",
	FrameFromRedirect:       "redirect",
	FrameFromFingerprintHub: "fingerprinthub",
	FrameFromWappalyzer:     "wappalyzer",
	FrameFromEhole:          "ehole",
	FrameFromGoby:           "goby",
}

func GetFrameFrom(s string) int {
	switch s {
	case "active":
		return FrameFromACTIVE
	case "404":
		return FrameFromNOTFOUND
	case "ico":
		return FrameFromICO
	case "guess":
		return FrameFromGUESS
	case "redirect":
		return FrameFromRedirect
	case "fingerprinthub":
		return FrameFromFingerprintHub
	case "wappalyzer":
		return FrameFromWappalyzer
	case "ehole":
		return FrameFromEhole
	case "goby":
		return FrameFromGoby

	default:
		return FrameFromDefault
	}
}

func NewFramework(name string, from int) *Framework {
	frame := &Framework{
		Name:          name,
		From:          from,
		Froms:         map[int]bool{from: true},
		Tags:          make([]string, 0),
		WFNAttributes: wfn.NewAttributesWithAny(),
	}
	frame.WFNAttributes.Product = name
	frame.WFNAttributes.Part = "a"
	if from >= FrameFromFingerprintHub {
		frame.AddTag(frameFromMap[from])
	}
	return frame
}

func NewFrameworkWithVersion(name string, from int, version string) *Framework {
	frame := NewFramework(name, from)
	frame.WFNAttributes.Version = version
	frame.Version = version
	return frame
}

type Framework struct {
	Name          string          `json:"name"`
	Version       string          `json:"version,omitempty"`
	From          int             `json:"-"` // 指纹可能会有多个来源, 指纹合并时会将多个来源记录到froms中
	Froms         map[int]bool    `json:"froms,omitempty"`
	Tags          []string        `json:"tags,omitempty"`
	IsFocus       bool            `json:"is_focus,omitempty"`
	Data          []byte          `json:"-"`
	WFNAttributes *wfn.Attributes `json:"-"`
}

func (f *Framework) String() string {
	var s strings.Builder
	if f.IsFocus {
		s.WriteString("focus:")
	}
	s.WriteString(f.Name)

	if f.Version != "" {
		s.WriteString(":" + strings.Replace(f.Version, ":", "_", -1))
	}

	if len(f.Froms) > 1 {
		s.WriteString(":(")
		var froms []string
		for from, _ := range f.Froms {
			froms = append(froms, frameFromMap[from])
		}
		s.WriteString(strings.Join(froms, " "))
		s.WriteString(")")
	} else {
		for from, _ := range f.Froms {
			if from != FrameFromDefault {
				s.WriteString(":")
				s.WriteString(frameFromMap[from])
			}
		}
	}
	return strings.TrimSpace(s.String())
}

func (f *Framework) CPE() string {
	return f.WFNAttributes.BindToFmtString()
}

func (f *Framework) URI() string {
	return f.WFNAttributes.BindToURI()
}

func (f *Framework) WFN() string {
	return f.WFNAttributes.String()
}

func (f *Framework) IsGuess() bool {
	var is bool
	for from, _ := range f.Froms {
		if from == FrameFromGUESS {
			is = true
		} else {
			return false
		}
	}
	return is
}

func (f *Framework) AddTag(tag string) {
	if !f.HasTag(tag) {
		f.Tags = append(f.Tags, tag)
	}
}

func (f *Framework) HasTag(tag string) bool {
	for _, t := range f.Tags {
		if t == tag {
			return true
		}
	}
	return false
}

type Frameworks map[string]*Framework

func (fs Frameworks) One() *Framework {
	for _, f := range fs {
		return f
	}
	return nil
}

func (fs Frameworks) List() []*Framework {
	var frameworks []*Framework
	for _, f := range fs {
		frameworks = append(frameworks, f)
	}
	return frameworks
}

func (fs Frameworks) Add(other *Framework) bool {
	other.Name = strings.ToLower(other.Name)
	if frame, ok := fs[other.Name]; ok {
		frame.Froms[other.From] = true
		frame.Tags = iutils.StringsUnique(append(frame.Tags, other.Tags...))
		if other.Version != "" && frame.Version == "" {
			frame.Version = other.Version
			frame.WFNAttributes.Version = other.Version
		}
		return false
	} else {
		fs[other.Name] = other
		return true
	}
}

func (fs Frameworks) Merge(other Frameworks) int {
	// name, tag 统一小写, 减少指纹库之间的差异
	var n int
	for _, f := range other {
		f.Name = strings.ToLower(f.Name)
		if fs.Add(f) {
			n += 1
		}
	}
	return n
}

func (fs Frameworks) String() string {
	if fs == nil {
		return ""
	}
	frameworkStrs := make([]string, len(fs))
	i := 0
	for _, f := range fs {
		if NoGuess && f.IsGuess() {
			continue
		}
		frameworkStrs[i] = f.String()
		i++
	}
	return strings.Join(frameworkStrs, "||")
}

func (fs Frameworks) GetNames() []string {
	if fs == nil {
		return nil
	}
	var titles []string
	for _, f := range fs {
		if !f.IsGuess() {
			titles = append(titles, f.Name)
		}
	}
	return titles
}

func (fs Frameworks) URI() []string {
	if fs == nil {
		return nil
	}
	var uris []string
	for _, f := range fs {
		uris = append(uris, f.URI())
	}
	return uris
}

func (fs Frameworks) CPE() []string {
	if fs == nil {
		return nil
	}
	var cpes []string
	for _, f := range fs {
		cpes = append(cpes, f.CPE())
	}
	return cpes
}

func (fs Frameworks) WFN() []string {
	if fs == nil {
		return nil
	}
	var wfns []string
	for _, f := range fs {
		wfns = append(wfns, f.WFN())
	}
	return wfns
}

func (fs Frameworks) IsFocus() bool {
	if fs == nil {
		return false
	}
	for _, f := range fs {
		if f.IsFocus {
			return true
		}
	}
	return false
}

func (fs Frameworks) HasTag(tag string) bool {
	for _, f := range fs {
		if f.HasTag(tag) {
			return true
		}
	}
	return false
}

func (fs Frameworks) HasFrom(from string) bool {
	for _, f := range fs {
		if f.Froms[GetFrameFrom(from)] {
			return true
		}
	}
	return false
}
