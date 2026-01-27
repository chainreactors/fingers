package fingers

import (
	"errors"

	"github.com/chainreactors/fingers/common"
	"github.com/chainreactors/fingers/favicon"
	"github.com/chainreactors/fingers/resources"
	"gopkg.in/yaml.v3"
)

const (
	HTTPProtocol = "http"
	TCPProtocol  = "tcp"
	UDPProtocol  = "udp"
)

func NewEngine(httpFingers, socketFingers Fingers) (*FingersEngine, error) {
	engine := &FingersEngine{
		HTTPFingers:   httpFingers,
		SocketFingers: socketFingers,
		Favicons:      favicon.NewFavicons(),
	}

	err := engine.Compile()
	if err != nil {
		return nil, err
	}
	return engine, nil
}

func NewFingersEngine(httpData, socketData, portData []byte) (*FingersEngine, error) {
	// httpdata must be not nil
	// socketdata can be nil
	if resources.PrePort == nil && portData != nil {
		// 临时设置 PortData 以供 LoadPorts 使用
		resources.PortData = portData
		_, err := resources.LoadPorts()
		if err != nil {
			return nil, err
		}
	}

	httpfs, err := LoadFingers(httpData)
	if err != nil {
		return nil, err
	}

	socketfs, err := LoadFingers(socketData)
	if err != nil {
		return nil, err
	}

	return NewEngine(httpfs, socketfs)
}

type FingersEngine struct {
	HTTPFingers              Fingers
	HTTPFingersActiveFingers Fingers
	SocketFingers            Fingers
	SocketGroup              FingerMapper
	Favicons                 *favicon.FaviconsEngine
	MatchDetailEnabled       bool
}

func (engine *FingersEngine) Name() string {
	return "fingers"
}

func (engine *FingersEngine) Len() int {
	return len(engine.HTTPFingers) + len(engine.SocketFingers)
}

// addToSocketGroup 将指纹添加到SocketGroup中
func (engine *FingersEngine) addToSocketGroup(f *Finger) {
	if engine.SocketGroup == nil {
		engine.SocketGroup = make(FingerMapper)
	}
	if f.DefaultPort != nil {
		for _, port := range resources.PrePort.ParsePortSlice(f.DefaultPort) {
			engine.SocketGroup[port] = append(engine.SocketGroup[port], f)
		}
	} else {
		engine.SocketGroup["0"] = append(engine.SocketGroup["0"], f)
	}
}

func (engine *FingersEngine) Compile() error {
	var err error
	if engine.HTTPFingers == nil {
		return errors.New("fingers is nil")
	}
	engine.HTTPFingersActiveFingers = nil
	for _, finger := range engine.HTTPFingers {
		finger.EnableMatchDetail = engine.MatchDetailEnabled
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
			finger.EnableMatchDetail = engine.MatchDetailEnabled
			err = finger.Compile(true)
			if err != nil {
				return err
			}
			engine.addToSocketGroup(finger)
		}
	}
	return nil
}

func (engine *FingersEngine) Append(fingers Fingers) error {
	for _, f := range fingers {
		f.EnableMatchDetail = engine.MatchDetailEnabled
		err := f.Compile(false)
		if err != nil {
			return err
		}
		if f.Protocol == HTTPProtocol {
			engine.HTTPFingers = append(engine.HTTPFingers, f)
			if f.IsActive {
				engine.HTTPFingersActiveFingers = append(engine.HTTPFingersActiveFingers, f)
			}
		} else if f.Protocol == TCPProtocol {
			engine.SocketFingers = append(engine.SocketFingers, f)
			engine.addToSocketGroup(f)
		}
	}
	return nil
}

// SetMatchDetailEnabled toggles match detail collection on all fingers.
func (engine *FingersEngine) SetMatchDetailEnabled(enabled bool) {
	engine.MatchDetailEnabled = enabled
	for _, finger := range engine.HTTPFingers {
		finger.EnableMatchDetail = enabled
	}
	for _, finger := range engine.SocketFingers {
		finger.EnableMatchDetail = enabled
	}
}

// EnableMatchDetail enables detailed matcher metadata collection.
func (engine *FingersEngine) EnableMatchDetail() {
	engine.SetMatchDetailEnabled(true)
}

// LoadFromYAML loads fingerprints from YAML file or URL and appends them to the engine
// This method only supports YAML format for custom fingerprints
func (engine *FingersEngine) LoadFromYAML(path string) error {
	content, err := resources.LoadFingersFromYAML(path)
	if err != nil {
		return err
	}

	var fingers Fingers
	if err := yaml.Unmarshal(content, &fingers); err != nil {
		return err
	}

	return engine.Append(fingers)
}

func (engine *FingersEngine) SocketMatch(content []byte, port string, level int, sender Sender, callback Callback) (*common.Framework, *common.Vuln) {
	// socket service only match one fingerprint
	var alreadyFrameworks = make(map[string]bool)
	input := NewContent(content, "", false)
	var fs common.Frameworks
	var vs common.Vulns
	if port != "" {
		fs, vs = engine.SocketGroup[port].Match(input, level, sender, callback, true)
		if len(fs) > 0 {
			return fs.One(), vs.One()
		}
		for _, fs := range engine.SocketGroup[port] {
			alreadyFrameworks[fs.Name] = true
		}
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

// WebMatch 实现Web指纹匹配
func (engine *FingersEngine) WebMatch(content []byte) common.Frameworks {
	fs, _ := engine.HTTPMatch(content, "")
	return fs
}

// ServiceMatch 实现Service指纹匹配
func (engine *FingersEngine) ServiceMatch(host string, portStr string, level int, sender common.ServiceSender, callback common.ServiceCallback) *common.ServiceResult {
	if sender == nil {
		return nil
	}

	// 创建自适应的Callback
	fingersCallback := func(framework *common.Framework, vuln *common.Vuln) {
		if callback != nil {
			result := &common.ServiceResult{
				Framework: framework,
				Vuln:      vuln,
			}
			callback(result)
		}
	}

	// 创建适配器将common.ServiceSender转换为fingers.Sender
	// fingers.Sender: func([]byte) ([]byte, bool)
	// common.ServiceSender.Send(host, port, data) ([]byte, error)
	fingersSender := Sender(func(data []byte) ([]byte, bool) {
		response, err := sender.Send(host, portStr, data, "tcp")
		if err != nil {
			return nil, false
		}
		return response, true
	})

	framework, vuln := engine.SocketMatch(nil, portStr, level, fingersSender, fingersCallback)

	return &common.ServiceResult{
		Framework: framework,
		Vuln:      vuln,
	}
}

func (engine *FingersEngine) Capability() common.EngineCapability {
	return common.EngineCapability{
		SupportWeb:     true, // fingers支持Web指纹
		SupportService: true, // fingers支持Service指纹
	}
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
