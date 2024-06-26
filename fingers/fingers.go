package fingers

import (
	"bytes"
	"github.com/chainreactors/fingers/common"
	"github.com/chainreactors/utils/encode"
	"regexp"
	"strings"

	"github.com/chainreactors/logs"
)

var (
	OPSEC     = false
	FingerLog = logs.Log
)

type Finger struct {
	Name        string   `yaml:"name" json:"name"`
	Protocol    string   `yaml:"protocol,omitempty" json:"protocol"`
	Link        string   `yaml:"link,omitempty" json:"link,omitempty"`
	DefaultPort []string `yaml:"default_port,omitempty" json:"default_port,omitempty"`
	Focus       bool     `yaml:"focus,omitempty" json:"focus,omitempty"`
	Rules       Rules    `yaml:"rule,omitempty" json:"rule,omitempty"`
	Tags        []string `yaml:"tag,omitempty" json:"tag,omitempty"`
	Opsec       bool     `yaml:"opsec,omitempty" json:"opsec,omitempty"`
	IsActive    bool     `yaml:"-" json:"-"`
}

func (finger *Finger) Compile(portHandler func([]string) []string) error {
	if finger.Protocol == "" {
		finger.Protocol = "http"
	}

	if len(finger.DefaultPort) == 0 {
		if finger.Protocol == "http" {
			finger.DefaultPort = []string{"80"}
		}
	} else if portHandler != nil {
		finger.DefaultPort = portHandler(finger.DefaultPort)
	}

	err := finger.Rules.Compile(finger.Name)
	if err != nil {
		return err
	}

	for _, r := range finger.Rules {
		if r.IsActive {
			finger.IsActive = true
			break
		}
	}
	return nil
}

func (finger *Finger) ToResult(hasFrame, hasVuln bool, ver string, index int) (frame *common.Framework, vuln *common.Vuln) {
	if index >= len(finger.Rules) {
		return nil, nil
	}

	if hasFrame {
		if ver != "" {
			frame = common.NewFrameworkWithVersion(finger.Name, common.FrameFromFingers, ver)
		} else if finger.Rules[index].Version != "_" {
			frame = common.NewFrameworkWithVersion(finger.Name, common.FrameFromFingers, finger.Rules[index].Version)
		} else {
			frame = common.NewFramework(finger.Name, common.FrameFromFingers)
			//frame = &common.Framework{Name: finger.Name}
		}
	}

	if hasVuln {
		if finger.Rules[index].Vuln != "" {
			vuln = &common.Vuln{Name: finger.Rules[index].Vuln, SeverityLevel: HIGH, Framework: frame}
		} else if finger.Rules[index].Info != "" {
			vuln = &common.Vuln{Name: finger.Rules[index].Info, SeverityLevel: INFO, Framework: frame}
		} else {
			vuln = &common.Vuln{Name: finger.Name, SeverityLevel: INFO}
		}
		if finger.IsActive {
			vuln.Detail = map[string][]string{"path": []string{finger.Rules[index].SendDataStr}}
		}
	}

	return frame, vuln
}

func (finger *Finger) Match(content *Content, level int, sender Sender) (*common.Framework, *common.Vuln, bool) {
	// sender用来处理需要主动发包的场景, 因为不通工具中的传入指不相同, 因此采用闭包的方式自定义result进行处理, 并允许添加更多的功能.
	// 例如在spray中, sender可以用来配置header等, 也可以进行特定的path拼接
	// 如果sender留空只进行被动的指纹判断, 将无视rules中的senddata字段

	for i, rule := range finger.Rules {
		var ishttp bool
		var isactive bool
		if finger.Protocol == "http" {
			ishttp = true
		}
		var c []byte
		var ok bool
		// 主动发包获取指纹
		if level >= rule.Level && rule.SendData != nil && sender != nil {
			if OPSEC == true && finger.Opsec == true {
				FingerLog.Debugf("(opsec!!!) skip active finger %s scan", finger.Name)
			} else {
				c, ok = sender(rule.SendData)
				if ok {
					isactive = true
					if ishttp {
						content.UpdateContent(c)
					} else {
						content.Content = c
					}
				}
			}
		}
		hasFrame, hasVuln, ver := RuleMatcher(rule, content, ishttp)
		if hasFrame {
			frame, vuln := finger.ToResult(hasFrame, hasVuln, ver, i)
			if finger.Focus {
				frame.IsFocus = true
			}
			//if vuln == nil && isactive {
			//	vuln = &parsers.Vuln{Name: finger.Name + " detect", SeverityLevel: INFO, Detail: map[string]interface{}{"path": rule.SendDataStr}}
			//}

			if isactive {
				frame.From = common.FrameFromFingers
				frame.Froms = map[common.From]bool{common.FrameFromACTIVE: true}
			}
			for _, tag := range finger.Tags {
				frame.AddTag(tag)
			}
			return frame, vuln, true
		}
	}
	return nil, nil, false
}

func (finger *Finger) PassiveMatch(content *Content) (*common.Framework, *common.Vuln, bool) {
	for i, rule := range finger.Rules {
		var ishttp bool
		if finger.Protocol == "http" {
			ishttp = true
		}

		hasFrame, hasVuln, ver := RuleMatcher(rule, content, ishttp)
		if hasFrame {
			frame, vuln := finger.ToResult(hasFrame, hasVuln, ver, i)
			if finger.Focus {
				frame.IsFocus = true
			}
			//if vuln == nil && isactive {
			//	vuln = &common.Vuln{Name: finger.Name + " detect", SeverityLevel: INFO, Detail: map[string]interface{}{"path": rule.SendDataStr}}
			//}

			for _, tag := range finger.Tags {
				frame.AddTag(tag)
			}
			return frame, vuln, true
		}
	}
	return nil, nil, false
}

func (finger *Finger) ActiveMatch(level int, sender Sender) (*common.Framework, *common.Vuln, bool) {
	if sender == nil {
		return nil, nil, false
	}

	for i, rule := range finger.Rules {
		var ishttp bool
		if finger.Protocol == "http" {
			ishttp = true
		}
		// 主动发包获取指纹
		if !(level >= rule.Level && rule.SendData != nil) {
			return nil, nil, false
		}
		if OPSEC == true && finger.Opsec == true {
			FingerLog.Debugf("(opsec!!!) skip active finger %s scan", finger.Name)
			return nil, nil, false
		}
		content := &Content{}
		c, ok := sender(rule.SendData)
		if ok {
			if ishttp {
				content.UpdateContent(c)
			} else {
				content.Content = c
			}
		} else {
			return nil, nil, false
		}

		hasFrame, hasVuln, ver := RuleMatcher(rule, content, ishttp)
		if hasFrame {
			frame, vuln := finger.ToResult(hasFrame, hasVuln, ver, i)
			if finger.Focus {
				frame.IsFocus = true
			}
			//if vuln == nil && isactive {
			//	vuln = &common.Vuln{Name: finger.Name + " detect", SeverityLevel: INFO, Detail: map[string]interface{}{"path": rule.SendDataStr}}
			//}

			frame.From = common.FrameFromFingers
			frame.Froms = map[common.From]bool{common.FrameFromACTIVE: true}
			for _, tag := range finger.Tags {
				frame.AddTag(tag)
			}
			return frame, vuln, true
		}
	}
	return nil, nil, false
}

type Regexps struct {
	Body                  []string         `yaml:"body,omitempty" json:"body,omitempty"`
	MD5                   []string         `yaml:"md5,omitempty" json:"md5,omitempty"`
	MMH3                  []string         `yaml:"mmh3,omitempty" json:"mmh3,omitempty"`
	Regexp                []string         `yaml:"regexp,omitempty" json:"regexp,omitempty"`
	Version               []string         `yaml:"version,omitempty" json:"version,omitempty"`
	Cert                  []string         `yaml:"cert,omitempty" json:"cert,omitempty"`
	CompliedRegexp        []*regexp.Regexp `yaml:"-" json:"-"`
	CompiledVulnRegexp    []*regexp.Regexp `yaml:"-" json:"-"`
	CompiledVersionRegexp []*regexp.Regexp `yaml:"-" json:"-"`
	FingerName            string           `yaml:"-" json:"-"`
	Header                []string         `yaml:"header,omitempty" json:"header,omitempty"`
	Vuln                  []string         `yaml:"vuln,omitempty" json:"vuln,omitempty"`
}

func (r *Regexps) Compile() error {
	for _, reg := range r.Regexp {
		creg, err := compileRegexp("(?i)" + reg)
		if err != nil {
			return err
		}
		r.CompliedRegexp = append(r.CompliedRegexp, creg)
	}

	for _, reg := range r.Vuln {
		creg, err := compileRegexp("(?i)" + reg)
		if err != nil {
			return err
		}
		r.CompiledVulnRegexp = append(r.CompiledVulnRegexp, creg)
	}

	for _, reg := range r.Version {
		creg, err := compileRegexp(reg)
		if err != nil {
			return err
		}
		r.CompiledVersionRegexp = append(r.CompiledVersionRegexp, creg)
	}

	for i, b := range r.Body {
		r.Body[i] = strings.ToLower(b)
	}

	for i, h := range r.Header {
		r.Header[i] = strings.ToLower(h)
	}
	return nil
}

type Favicons struct {
	Path string   `yaml:"path,omitempty" json:"path,omitempty"`
	Mmh3 []string `yaml:"mmh3,omitempty" json:"mmh3,omitempty"`
	Md5  []string `yaml:"md5,omitempty" json:"md5,omitempty"`
}

type Rule struct {
	Version     string    `yaml:"version,omitempty" json:"version,omitempty"`
	Favicon     *Favicons `yaml:"favicon,omitempty" json:"favicon,omitempty"`
	Regexps     *Regexps  `yaml:"regexps,omitempty" json:"regexps,omitempty"`
	SendDataStr string    `yaml:"send_data,omitempty" json:"send_data,omitempty"`
	SendData    senddata  `yaml:"-" json:"-"`
	Info        string    `yaml:"info,omitempty" json:"info,omitempty"`
	Vuln        string    `yaml:"vuln,omitempty" json:"vuln,omitempty"`
	Level       int       `yaml:"level,omitempty" json:"level,omitempty"`
	FingerName  string    `yaml:"-" json:"-"`
	IsActive    bool      `yaml:"-" json:"-"`
}

func (r *Rule) Compile(name string) error {
	if r.Version == "" {
		r.Version = "_"
	}
	r.FingerName = name
	if r.SendDataStr != "" {
		r.SendData, _ = encode.DSLParser(r.SendDataStr)
		if r.Level == 0 {
			r.Level = 1
		}
		r.IsActive = true
	}

	if r.Regexps != nil {
		err := r.Regexps.Compile()
		if err != nil {
			return err
		}
	}

	return nil
}

type Rules []*Rule

func (rs Rules) Compile(name string) error {
	for _, r := range rs {
		err := r.Compile(name)
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *Rule) Match(content, header, body []byte) (bool, bool, string) {
	// 漏洞匹配优先
	for _, reg := range r.Regexps.CompiledVulnRegexp {
		res, ok := compiledMatch(reg, content)
		if ok {
			return true, true, res
		}
	}

	// 正则匹配
	for _, reg := range r.Regexps.CompliedRegexp {
		res, ok := compiledMatch(reg, content)
		if ok {
			FingerLog.Debugf("%s finger hit, regexp: %q", r.FingerName, reg.String())
			return true, false, res
		}
	}

	// http头匹配, http协议特有的匹配
	for _, headerStr := range r.Regexps.Header {
		if bytes.Contains(header, []byte(headerStr)) {
			FingerLog.Debugf("%s finger hit, header: %s", r.FingerName, headerStr)
			return true, false, ""
		}
	}

	if len(body) == 0 {
		return false, false, ""
	}

	// body匹配
	for _, bodyReg := range r.Regexps.Body {
		if bytes.Contains(body, []byte(bodyReg)) {
			FingerLog.Debugf("%s finger hit, body: %q", r.FingerName, bodyReg)
			return true, false, ""
		}
	}

	// MD5 匹配
	for _, md5s := range r.Regexps.MD5 {
		if md5s == encode.Md5Hash(body) {
			FingerLog.Debugf("%s finger hit, md5: %s", r.FingerName, md5s)
			return true, false, ""
		}
	}

	// mmh3 匹配
	for _, mmh3s := range r.Regexps.MMH3 {
		if mmh3s == encode.Mmh3Hash32(body) {
			FingerLog.Debugf("%s finger hit, mmh3: %s", r.FingerName, mmh3s)
			return true, false, ""
		}
	}

	return false, false, ""
}

func (r *Rule) MatchCert(content string) bool {
	for _, cert := range r.Regexps.Cert {
		if strings.Contains(content, cert) {
			return true
		}
	}
	return false
}
