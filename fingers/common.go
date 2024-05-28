package fingers

import (
	"encoding/json"
	"github.com/chainreactors/fingers/common"
	"github.com/chainreactors/utils"
)

// LoadFingers 加载指纹 迁移到fingers包从, 允许其他服务调用
func LoadFingers(content []byte) (fingers Fingers, err error) {
	err = json.Unmarshal(content, &fingers)
	if err != nil {
		return nil, err
	}

	for _, finger := range fingers {
		err := finger.Compile(utils.ParsePorts)
		if err != nil {
			return nil, err
		}
	}

	return fingers, nil
}

type FingerMapper map[string]Fingers

type Fingers []*Finger

func (fs Fingers) GroupByPort() FingerMapper {
	fingermap := make(FingerMapper)
	for _, f := range fs {
		if f.DefaultPort == nil {
			for _, port := range f.DefaultPort {
				fingermap[port] = append(fingermap[port], f)
			}
		} else {
			fingermap["0"] = append(fingermap["0"], f)
		}
	}
	return fingermap
}

func (fs Fingers) GroupByMod() (Fingers, Fingers) {
	var active, passive Fingers
	for _, f := range fs {
		if f.IsActive {
			active = append(active, f)
		} else {
			passive = append(passive, f)
		}
	}
	return active, passive
}

func (fs Fingers) PassiveMatch(input map[string]interface{}, stopAtFirst bool) (common.Frameworks, common.Vulns) {
	frames := make(common.Frameworks)
	vulns := make(common.Vulns)
	for _, finger := range fs {
		// sender置空, 所有的发包交给spray的pool
		frame, vuln, ok := finger.PassiveMatch(input)
		if ok {
			frames.Add(frame)
			if vuln != nil {
				vulns[vuln.Name] = vuln
			}
			if stopAtFirst {
				break
			}
		}
	}
	return frames, vulns
}

func (fs Fingers) ActiveMatch(level int, sender Sender, callback Callback, stopAtFirst bool) (common.Frameworks, common.Vulns) {
	frames := make(common.Frameworks)
	vulns := make(common.Vulns)
	for _, finger := range fs {
		frame, vuln, ok := finger.ActiveMatch(level, sender)
		if callback != nil {
			callback(frame, vuln)
		}
		if ok {
			frames.Add(frame)
			if vuln != nil {
				vulns[vuln.Name] = vuln
			}
			if stopAtFirst {
				break
			}
		}
	}
	return frames, vulns
}

func (fs Fingers) Match(input map[string]interface{}, level int, sender Sender, callback Callback, stopAtFirst bool) (common.Frameworks, common.Vulns) {
	frames := make(common.Frameworks)
	vulns := make(common.Vulns)
	for _, finger := range fs {
		frame, vuln, ok := finger.Match(input, level, sender)
		if callback != nil {
			callback(frame, vuln)
		}
		if ok {
			ok = true
			frames.Add(frame)
			if vuln != nil {
				vulns.Add(vuln)
			}
			if stopAtFirst {
				break
			}
		}
	}
	return frames, vulns
}
