package common

import (
	"github.com/chainreactors/utils/iutils"
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
	default:
		return FrameFromDefault
	}
}

type Framework struct {
	Name    string       `json:"name"`
	Version string       `json:"version,omitempty"`
	From    int          `json:"-"` // 指纹可能会有多个来源, 指纹合并时会将多个来源记录到froms中
	Froms   map[int]bool `json:"froms,omitempty"`
	Tags    []string     `json:"tags,omitempty"`
	IsFocus bool         `json:"is_focus,omitempty"`
	Data    []byte       `json:"-"`
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
		for from, _ := range f.Froms {
			s.WriteString(frameFromMap[from] + " ")
		}
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

func (f *Framework) HasTag(tag string) bool {
	for _, t := range f.Tags {
		if t == tag {
			return true
		}
	}
	return false
}

type Frameworks map[string]*Framework

func (fs Frameworks) Add(other *Framework) {
	other.Name = strings.ToLower(other.Name)
	if frame, ok := fs[other.Name]; ok {
		frame.Froms[other.From] = true
	} else {
		other.Froms = map[int]bool{other.From: true}
		fs[other.Name] = other
	}
}

func (fs Frameworks) Merge(other Frameworks) {
	// name, tag 统一小写, 减少指纹库之间的差异
	for _, f := range other {
		f.Name = strings.ToLower(f.Name)
		if frame, ok := fs[f.Name]; ok {
			if frame.Version == "" && f.Version != "" {
				frame.Version = f.Version
			}
			if len(f.Tags) > 0 {
				for i, tag := range f.Tags {
					f.Tags[i] = strings.ToLower(tag)
				}
				frame.Tags = iutils.StringsUnique(append(frame.Tags, f.Tags...))
			}
			frame.Froms[FrameFromFingerprintHub] = true
		} else {
			fs[f.Name] = f
		}
	}
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
