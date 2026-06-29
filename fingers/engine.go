package fingers

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/chainreactors/fingers/common"
	"github.com/chainreactors/fingers/favicon"
	"github.com/chainreactors/fingers/resources"
	"github.com/chainreactors/utils"
	"gopkg.in/yaml.v3"
)

const (
	HTTPProtocol = "http"
	TCPProtocol  = "tcp"
	UDPProtocol  = "udp"
)

func NewEngine(httpFingers, socketFingers Fingers) (*FingersEngine, error) {
	return NewEngineWithPreset(httpFingers, socketFingers, nil)
}

func NewEngineWithPreset(httpFingers, socketFingers Fingers, preset *utils.PortPreset) (*FingersEngine, error) {
	engine := &FingersEngine{
		HTTPFingers:   httpFingers,
		SocketFingers: socketFingers,
		Favicons:      favicon.NewFavicons(),
		portPreset:    preset,
	}

	err := engine.Compile()
	if err != nil {
		return nil, err
	}
	return engine, nil
}

func NewFingersEngine(httpData, socketData, portData []byte) (*FingersEngine, error) {
	var preset *utils.PortPreset
	if portData != nil {
		var ports []*utils.PortConfig
		if err := yaml.Unmarshal(portData, &ports); err != nil {
			return nil, err
		}
		preset = utils.NewPortPreset(ports)
	} else if resources.PrePort != nil {
		preset = resources.PrePort
	}

	httpfs, err := LoadFingers(httpData)
	if err != nil {
		return nil, err
	}

	socketfs, err := LoadFingers(socketData)
	if err != nil {
		return nil, err
	}

	return NewEngineWithPreset(httpfs, socketfs, preset)
}

type FingersEngine struct {
	HTTPFingers              Fingers
	HTTPFingersActiveFingers Fingers
	SocketFingers            Fingers
	SocketGroup              FingerMapper
	Favicons                 *favicon.FaviconsEngine
	MatchDetailEnabled       bool
	httpKeywordIndex         *KeywordIndex
	portPreset               *utils.PortPreset
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
		ports := engine.parsePortSlice(f.DefaultPort)
		for _, port := range ports {
			engine.SocketGroup[port] = append(engine.SocketGroup[port], f)
		}
	} else {
		engine.SocketGroup["0"] = append(engine.SocketGroup["0"], f)
	}
}

func (engine *FingersEngine) parsePortSlice(ports []string) []string {
	if engine.portPreset != nil {
		return engine.portPreset.ParsePortSlice(ports)
	}
	return ports
}

// PortPreset returns the engine's port preset (may be nil).
func (engine *FingersEngine) PortPreset() *utils.PortPreset {
	return engine.portPreset
}

func (engine *FingersEngine) Compile() error {
	var err error
	if engine.HTTPFingers == nil {
		return errors.New("fingers is nil")
	}
	engine.HTTPFingersActiveFingers = nil
	for _, finger := range engine.HTTPFingers {
		finger.EnableMatchDetail = engine.MatchDetailEnabled
		err = finger.CompileWithPreset(false, engine.portPreset)
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

	engine.httpKeywordIndex = NewKeywordIndex(engine.HTTPFingers)

	if engine.SocketFingers != nil {
		for _, finger := range engine.SocketFingers {
			finger.EnableMatchDetail = engine.MatchDetailEnabled
			err = finger.CompileWithPreset(true, engine.portPreset)
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
		err := f.CompileWithPreset(false, engine.portPreset)
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
	engine.httpKeywordIndex = NewKeywordIndex(engine.HTTPFingers)
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
	input := NewContent(content, cert, true)
	if engine.httpKeywordIndex != nil {
		return engine.HTTPFingers.ACPassiveMatch(input, engine.httpKeywordIndex, false)
	}
	return engine.HTTPFingers.PassiveMatch(input, false)
}

func (engine *FingersEngine) HTTPActiveMatch(baseURL string, level int, transport http.RoundTripper, callback Callback) (common.Frameworks, common.Vulns) {
	// 将 http.RoundTripper 适配为 Sender
	sender := roundTripperToSender(transport, baseURL)
	return engine.HTTPFingersActiveFingers.ActiveMatch(level, sender, callback, false)
}

// roundTripperToSender 将 http.RoundTripper 适配为 Sender
// 这样可以让内部的 ActiveMatch 继续使用 Sender 接口，同时对外统一使用 http.RoundTripper
func roundTripperToSender(transport http.RoundTripper, baseURL string) Sender {
	return func(data []byte) ([]byte, bool) {
		// data 是路径，例如 "/admin" 或 "/api/version"
		path := string(data)

		// 构造完整 URL
		fullURL := baseURL + path

		// 创建 http.Request
		req, err := http.NewRequest("GET", fullURL, nil)
		if err != nil {
			return nil, false
		}

		// 通过 RoundTripper 发送请求
		resp, err := transport.RoundTrip(req)
		if err != nil {
			return nil, false
		}
		defer resp.Body.Close()

		// 读取响应并序列化为字节流
		var buf bytes.Buffer

		// 写入状态行
		fmt.Fprintf(&buf, "%s %s\r\n", resp.Proto, resp.Status)

		// 写入 headers
		for key, values := range resp.Header {
			for _, value := range values {
				fmt.Fprintf(&buf, "%s: %s\r\n", key, value)
			}
		}

		// 空行分隔 headers 和 body
		buf.WriteString("\r\n")

		// 写入 body
		if resp.Body != nil {
			io.Copy(&buf, resp.Body)
		}

		return buf.Bytes(), true
	}
}
