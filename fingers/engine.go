package fingers

import (
	"errors"
	"github.com/chainreactors/fingers/common"
	"github.com/chainreactors/fingers/resources"
)

func NewFingersEngine(httpdata, socketdata []byte) (*FingersEngine, error) {
	// httpdata must be not nil
	// socketdata can be nil
	err := resources.LoadPorts()
	if err != nil {
		return nil, err
	}

	httpfs, err := LoadFingers(httpdata)
	if err != nil {
		return nil, err
	}

	engine := &FingersEngine{
		HTTPFingers: httpfs,
		Favicons:    common.NewFavicons(),
	}

	if socketdata != nil {
		engine.SocketFingers, err = LoadFingers(socketdata)
		if err != nil {
			return nil, err
		}
	}

	err = engine.Compile()
	if err != nil {
		return nil, err
	}
	return engine, nil
}

type FingersEngine struct {
	HTTPFingers              Fingers
	HTTPFingersActiveFingers Fingers
	SocketFingers            Fingers
	SocketGroup              FingerMapper
	Favicons                 *common.Favicons
}

func (engine *FingersEngine) Compile() error {
	var err error
	if engine.HTTPFingers == nil {
		return errors.New("fingers is nil")
	}
	for _, finger := range engine.HTTPFingers {
		err = finger.Compile(false)
		if err != nil {
			return err
		}
		if finger.IsActive {
			engine.HTTPFingersActiveFingers = append(engine.HTTPFingersActiveFingers, finger)
		}
	}

	//初始化favicon规则
	for _, finger := range engine.HTTPFingers {
		for _, rule := range finger.Rules {
			if rule.Favicon != nil {
				for _, mmh3 := range rule.Favicon.Mmh3 {
					engine.Favicons.Mmh3Fingers[mmh3] = finger.Name
				}
				for _, md5 := range rule.Favicon.Md5 {
					engine.Favicons.Md5Fingers[md5] = finger.Name
				}
			}
		}
	}

	if engine.SocketFingers != nil {
		for _, finger := range engine.SocketFingers {
			err = finger.Compile(true)
			if err != nil {
				return err
			}
		}
		engine.SocketGroup = engine.SocketFingers.GroupByPort()
	}
	return nil
}

func (engine *FingersEngine) SocketMatch(content []byte, port string, level int, sender Sender, callback Callback) (*common.Framework, *common.Vuln) {
	// socket service only match one fingerprint
	var alreadyFrameworks = make(map[string]bool)
	input := NewContent(content, "", false)
	fs, vs := engine.SocketGroup[port].Match(input, level, sender, callback, true)
	if len(fs) > 0 {
		return fs.One(), vs.One()
	}
	for _, fs := range engine.SocketGroup[port] {
		alreadyFrameworks[fs.Name] = true
	}

	fs, vs = engine.SocketGroup["0"].Match(input, level, sender, callback, true)
	if len(fs) > 0 {
		return fs.One(), vs.One()
	}
	for _, fs := range engine.SocketGroup["0"] {
		alreadyFrameworks[fs.Name] = true
	}

	for _, fs := range engine.SocketGroup {
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

func (engine *FingersEngine) HTTPMatch(content []byte, cert string) (common.Frameworks, common.Vulns) {
	// input map[string]interface{}
	// content: []byte
	// cert: string

	return engine.HTTPFingers.PassiveMatch(NewContent(content, cert, true), false)
}

func (engine *FingersEngine) HTTPActiveMatch(level int, sender Sender, callback Callback) (common.Frameworks, common.Vulns) {
	return engine.HTTPFingersActiveFingers.ActiveMatch(level, sender, callback, false)
}
