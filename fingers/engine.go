package fingers

import (
	"github.com/chainreactors/fingers/common"
	"github.com/chainreactors/logs"
)

type Sender func([]byte) ([]byte, bool)

var HashEngine = &HashRules{
	Md5Fingers:  make(map[string]string),
	Mmh3Fingers: make(map[string]string),
}

func (engine *HashRules) Load(fingers Fingers) {
	for _, finger := range fingers {
		for _, rule := range finger.Rules {
			if rule.Favicon != nil {
				for _, mmh3 := range rule.Favicon.Mmh3 {
					engine.Mmh3Fingers[mmh3] = finger.Name
				}
				for _, md5 := range rule.Favicon.Md5 {
					engine.Md5Fingers[md5] = finger.Name
				}
			}
		}
	}
}

type HashRules struct {
	Md5Fingers  map[string]string
	Mmh3Fingers map[string]string
}

func (engine *HashRules) FaviconMatch(md5, mmh3 string) *common.Framework {
	var frame *common.Framework
	if engine.Md5Fingers[md5] != "" {
		frame = &common.Framework{Name: engine.Md5Fingers[md5], From: common.FrameFromICO}
		return frame
	}

	if engine.Mmh3Fingers[mmh3] != "" {
		frame = &common.Framework{Name: engine.Mmh3Fingers[mmh3], From: common.FrameFromICO}
		return frame
	}
	return nil
}

var FingersEngine = &FingersRules{
	Fingers:   Fingers{},
	FingerLog: logs.Log,
	HashRules: HashEngine,
}

type FingersRules struct {
	Fingers       Fingers
	ActiveFingers Fingers
	FingerLog     *logs.Logger
	*HashRules
}

func (engine *FingersRules) Load(content []byte) error {
	fingers, err := LoadFingers(content)
	if err != nil {
		return err
	}
	engine.Fingers = fingers
	for _, finger := range fingers {
		if finger.IsActive {
			engine.ActiveFingers = append(engine.ActiveFingers, finger)
		}
	}
	engine.HashRules.Load(fingers)
	return nil
}

func (engine *FingersRules) Match(content []byte, cert string) (common.Frameworks, common.Vulns) {
	// input map[string]interface{}
	// content: []byte
	// cert: string

	frames := make(common.Frameworks)
	vulns := make(common.Vulns)
	for _, finger := range engine.Fingers {
		// sender置空, 所有的发包交给spray的pool
		frame, vuln, ok := finger.Match(map[string]interface{}{"content": content, "cert": cert}, 0, nil)
		if ok {
			frames.Add(frame)
			if vuln != nil {
				vulns[vuln.Name] = vuln
			}
		}
	}
	return frames, vulns
}

func (engine *FingersRules) ActiveMatch(sender Sender) (common.Frameworks, common.Vulns) {
	frames := make(common.Frameworks)
	vulns := make(common.Vulns)
	for _, finger := range engine.ActiveFingers {
		frame, vuln, ok := finger.ActiveMatch(1, sender)
		if ok {
			frames.Add(frame)
			if vuln != nil {
				vulns[vuln.Name] = vuln
			}
		}
	}
	return frames, vulns
}
