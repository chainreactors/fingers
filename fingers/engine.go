package fingers

import (
	"errors"
	"github.com/chainreactors/fingers/common"
)

type Sender func([]byte) ([]byte, bool)

func (engine *FaviconRules) Load(fingers Fingers) {
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

type FaviconRules struct {
	Md5Fingers  map[string]string
	Mmh3Fingers map[string]string
}

func (engine *FaviconRules) FaviconMatch(md5, mmh3 string) *common.Framework {
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

type FingersRules struct {
	HTTPFingers              Fingers
	HTTPFingersActiveFingers Fingers
	SocketFingers            Fingers
	SocketGroupped           FingerMapper
	*FaviconRules
}

func (engine *FingersRules) Load() error {
	if engine.HTTPFingers == nil {
		return errors.New("fingers is nil")
	}
	for _, finger := range engine.HTTPFingers {
		if finger.IsActive {
			engine.HTTPFingersActiveFingers = append(engine.HTTPFingersActiveFingers, finger)
		}
	}

	engine.FaviconRules.Load(engine.HTTPFingers)
	if engine.SocketFingers != nil {
		engine.SocketGroupped = engine.SocketFingers.GroupByPort()
	}
	return nil
}

func (engine *FingersRules) SocketMatch(content []byte, port string, level int, sender Sender) (*common.Framework, *common.Vuln) {
	// socket service only match one fingerprint
	var alreadyFrameworks = make(map[string]bool)
	for _, finger := range engine.SocketGroupped[port] {
		frame, vuln, ok := finger.Match(map[string]interface{}{"content": content}, level, sender)
		if ok {
			return frame, vuln
		}
	}

	for _, fs := range engine.SocketGroupped {
		for _, finger := range fs {
			if _, ok := alreadyFrameworks[finger.Name]; ok {
				continue
			} else {
				alreadyFrameworks[finger.Name] = true
			}

			frame, vuln, ok := finger.Match(map[string]interface{}{"content": content}, level, sender)
			if ok {
				return frame, vuln
			}
		}
	}
	return nil, nil
}

func (engine *FingersRules) HTTPMatch(content []byte, cert string) (common.Frameworks, common.Vulns) {
	// input map[string]interface{}
	// content: []byte
	// cert: string

	frames := make(common.Frameworks)
	vulns := make(common.Vulns)
	for _, finger := range engine.HTTPFingers {
		// sender置空, 所有的发包交给spray的pool
		frame, vuln, ok := finger.PassiveMatch(map[string]interface{}{"content": content, "cert": cert})
		if ok {
			frames.Add(frame)
			if vuln != nil {
				vulns[vuln.Name] = vuln
			}
		}
	}
	return frames, vulns
}

func (engine *FingersRules) HTTPActiveMatch(level int, sender Sender) (common.Frameworks, common.Vulns) {
	frames := make(common.Frameworks)
	vulns := make(common.Vulns)
	for _, finger := range engine.HTTPFingersActiveFingers {
		frame, vuln, ok := finger.ActiveMatch(level, sender)
		if ok {
			frames.Add(frame)
			if vuln != nil {
				vulns[vuln.Name] = vuln
			}
		}
	}
	return frames, vulns
}

func NewFingersEngine(httpdata, socketdata []byte) (*FingersRules, error) {
	// httpdata must be not nil
	// socketdata can be nil

	httpfs, err := LoadFingers(httpdata)
	if err != nil {
		return nil, err
	}

	engine := &FingersRules{
		HTTPFingers: httpfs,
		FaviconRules: &FaviconRules{
			Md5Fingers:  make(map[string]string),
			Mmh3Fingers: make(map[string]string),
		},
	}
	if socketdata != nil {
		engine.SocketFingers, err = LoadFingers(socketdata)
	}

	err = engine.Load()
	if err != nil {
		return nil, err
	}
	return engine, nil
}
