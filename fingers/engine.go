package fingers

import (
	"errors"
	"github.com/chainreactors/fingers/common"
	"github.com/chainreactors/utils/encode"
)

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
		if err != nil {
			return nil, err
		}
	}

	err = engine.Load()
	if err != nil {
		return nil, err
	}
	return engine, nil
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

func (engine *FingersRules) SocketMatch(content []byte, port string, level int, sender Sender, callback Callback) (*common.Framework, *common.Vuln) {
	// socket service only match one fingerprint
	var alreadyFrameworks = make(map[string]bool)
	input := map[string]interface{}{"content": content}
	fs, vs := engine.SocketGroupped[port].Match(input, level, sender, callback, true)
	if len(fs) > 0 {
		return fs.One(), vs.One()
	}
	for _, fs := range engine.SocketGroupped[port] {
		alreadyFrameworks[fs.Name] = true
	}

	for _, fs := range engine.SocketGroupped {
		for _, finger := range fs {
			if _, ok := alreadyFrameworks[finger.Name]; ok {
				continue
			} else {
				alreadyFrameworks[finger.Name] = true
			}

			frame, vuln, ok := finger.Match(input, level, sender)
			if ok {
				if callback != nil {
					callback(frame, vuln)
				}
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

	return engine.HTTPFingers.PassiveMatch(map[string]interface{}{"content": content, "cert": cert}, false)
}

func (engine *FingersRules) HTTPActiveMatch(level int, sender Sender, callback Callback) (common.Frameworks, common.Vulns) {
	return engine.HTTPFingersActiveFingers.ActiveMatch(level, sender, callback, false)
}

type FaviconRules struct {
	Md5Fingers  map[string]string
	Mmh3Fingers map[string]string
}

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

func (engine *FaviconRules) HashMatch(md5, mmh3 string) *common.Framework {
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

func (engine *FaviconRules) ContentMatch(content []byte) *common.Framework {
	md5h := encode.Md5Hash(content)
	mmh3h := encode.Mmh3Hash32(content)
	return engine.HashMatch(md5h, mmh3h)
}
