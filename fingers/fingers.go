package fingers

import (
	"github.com/chainreactors/fingers/common"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/utils"
	"github.com/chainreactors/utils/encode"
)

var (
	OPSEC     = false
	FingerLog = logs.Log
)

type Finger struct {
	Name              string            `yaml:"name" json:"name" jsonschema:"required,title=Fingerprint Name,description=Unique identifier for the fingerprint,example=nginx"`
	Attributes        common.Attributes `yaml:",inline" json:",inline"`
	Author            string            `yaml:"author,omitempty" json:"author,omitempty" jsonschema:"title=Author,description= Finger template author,nullable"`
	Description       string            `yaml:"description,omitempty" json:"description,omitempty" jsonschema:"title=Description,description= Finger template description,nullable"`
	Protocol          string            `yaml:"protocol,omitempty" json:"protocol,omitempty" jsonschema:"title=Protocol,description=Network protocol type,nullable,enum=http,enum=tcp,enum=udp,default=http,example=http"`
	Link              string            `yaml:"link,omitempty" json:"link,omitempty" jsonschema:"title=Link,description=Reference URL for the software,nullable,format=uri,example=https://nginx.org"`
	DefaultPort       []string          `yaml:"default_port,omitempty" json:"default_port,omitempty" jsonschema:"title=Default Ports,description=Default ports used by this service,nullable,example=80,example=443"`
	Focus             bool              `yaml:"focus,omitempty" json:"focus,omitempty" jsonschema:"title=Focus,description=Whether this is a high-priority fingerprint,default=false"`
	SendDataStr       string            `yaml:"send_data,omitempty" json:"send_data,omitempty" jsonschema:"title=Send Data,description=Data to send for active probing at level 1,nullable,example=/nacos/"`
	SendData          senddata          `yaml:"-" json:"-"`
	Rules             Rules             `yaml:"rule,omitempty" json:"rule,omitempty" jsonschema:"required,title=Rules,description=Matching rules for fingerprint detection"`
	Tags              []string          `yaml:"tag,omitempty" json:"tag,omitempty" jsonschema:"title=Tags,description=Category tags for classification,nullable,example=web,example=server"`
	Level             int               `yaml:"level,omitempty" json:"level,omitempty" jsonschema:"title=Level,description=Fingerprint detection level,default=0"`
	Opsec             bool              `yaml:"opsec,omitempty" json:"opsec,omitempty" jsonschema:"title=OPSEC,description=Whether this fingerprint uses operational security measures,default=false"`
	EnableMatchDetail bool              `yaml:"-" json:"-"`
	IsActive          bool              `yaml:"-" json:"-"`
}

func (finger *Finger) Compile(caseSensitive bool) error {
	if finger.Protocol == "" {
		finger.Protocol = HTTPProtocol
	}

	if len(finger.DefaultPort) == 0 {
		if finger.Protocol == HTTPProtocol {
			finger.DefaultPort = []string{"80"}
		}
	} else if utils.PrePort != nil {
		finger.DefaultPort = utils.ParsePortsSlice(finger.DefaultPort)
	}

	if finger.SendDataStr != "" {
		finger.SendData, _ = encode.DSLParser(finger.SendDataStr)
		if finger.Level == 0 {
			finger.Level = 1
		}
	}

	err := finger.Rules.Compile(finger.Name, caseSensitive)
	if err != nil {
		return err
	}

	finger.RefreshActive()
	return nil
}

// RefreshActive recomputes whether this finger has any active rules.
func (finger *Finger) RefreshActive() {
	finger.IsActive = finger.SendDataStr != ""
	for _, r := range finger.Rules {
		r.RefreshActive()
		if r.IsActive {
			finger.IsActive = true
		}
	}
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
			if sendDataStr := finger.Rules[index].ActiveSendDataStr(finger.SendDataStr); sendDataStr != "" {
				vuln.Detail = map[string][]string{"path": []string{sendDataStr}}
			}
		}
	}

	frame.Vendor = finger.Attributes.Vendor
	frame.Product = finger.Attributes.Product
	return frame, vuln
}

// annotateRuleHit records which rule, matcher, and send_data produced the hit on the framework.
func (finger *Finger) annotateRuleHit(frame *common.Framework, index int, detail *common.MatchDetail, sendData string) {
	if frame == nil || !finger.EnableMatchDetail {
		return
	}
	matchDetail := &common.MatchDetail{
		RuleIndex: index,
		SendData:  sendData,
	}
	if detail != nil {
		matchDetail.MatcherType = detail.MatcherType
		matchDetail.MatcherIndex = detail.MatcherIndex
		matchDetail.MatcherValue = detail.MatcherValue
	}
	frame.MatchDetail = matchDetail
}

// buildActiveResult constructs a result from an active hit and normalizes metadata.
func (finger *Finger) buildActiveResult(index int, hasVuln bool, ver string, detail *common.MatchDetail, sendData string) (*common.Framework, *common.Vuln) {
	frame, vuln := finger.ToResult(true, hasVuln, ver, index)
	if frame == nil {
		return nil, vuln
	}
	if finger.Focus {
		frame.IsFocus = true
	}
	frame.From = common.FrameFromFingers
	frame.Froms = map[common.From]bool{common.FrameFromACTIVE: true}
	for _, tag := range finger.Tags {
		frame.AddTag(tag)
	}
	finger.annotateRuleHit(frame, index, detail, sendData)
	return frame, vuln
}

// activeProbeAll performs active probing across all rules and payloads.
// It records the first match but does not short-circuit sending.
func (finger *Finger) activeProbeAll(level int, sender Sender) (*common.Framework, *common.Vuln, bool) {
	if sender == nil || level <= 0 {
		return nil, nil, false
	}
	if OPSEC == true && finger.Opsec == true {
		FingerLog.Debugf("(opsec!!!) skip active finger %s scan", finger.Name)
		return nil, nil, false
	}

	ishttp := finger.Protocol == HTTPProtocol
	var firstFrame *common.Framework
	var firstVuln *common.Vuln
	for i, rule := range finger.Rules {
		for _, payload := range rule.ActiveSendDataList(level, finger.SendData) {
			activeContent := &Content{}
			resp, ok := sender(payload)
			if !ok {
				continue
			}
			if ishttp {
				activeContent.UpdateContent(resp)
			} else {
				activeContent.Content = resp
			}

			hasFrame, hasVuln, ver, detail := RuleMatcher(rule, activeContent, ishttp)
			if hasFrame && firstFrame == nil {
				firstFrame, firstVuln = finger.buildActiveResult(i, hasVuln, ver, detail, string(payload))
			}
		}
	}
	if firstFrame != nil {
		return firstFrame, firstVuln, true
	}
	return nil, nil, false
}

func (finger *Finger) Match(content *Content, level int, sender Sender) (*common.Framework, *common.Vuln, bool) {
	// sender用来处理需要主动发包的场景, 因为不通工具中的传入指不相同, 因此采用闭包的方式自定义result进行处理, 并允许添加更多的功能.
	// 例如在spray中, sender可以用来配置header等, 也可以进行特定的path拼接
	// 如果sender留空只进行被动的指纹判断, 将无视rules中的senddata字段

	ishttp := finger.Protocol == HTTPProtocol

	// 主动阶段：遍历所有 rule，发送完整 send_data（记录首个命中，但不提前返回）
	if frame, vuln, ok := finger.activeProbeAll(level, sender); ok {
		return frame, vuln, true
	}

	// 被动阶段：不依赖主动发包结果
	for i, rule := range finger.Rules {
		hasFrame, hasVuln, ver, detail := RuleMatcher(rule, content, ishttp)
		if hasFrame {
			frame, vuln := finger.ToResult(hasFrame, hasVuln, ver, i)
			if finger.Focus {
				frame.IsFocus = true
			}
			for _, tag := range finger.Tags {
				frame.AddTag(tag)
			}
			finger.annotateRuleHit(frame, i, detail, "")
			return frame, vuln, true
		}
	}
	return nil, nil, false
}

func (finger *Finger) PassiveMatch(content *Content) (*common.Framework, *common.Vuln, bool) {
	for i, rule := range finger.Rules {
		var ishttp bool
		if finger.Protocol == HTTPProtocol {
			ishttp = true
		}

		hasFrame, hasVuln, ver, detail := RuleMatcher(rule, content, ishttp)
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
			finger.annotateRuleHit(frame, i, detail, "")
			return frame, vuln, true
		}
	}
	return nil, nil, false
}

func (finger *Finger) ActiveMatch(level int, sender Sender) (*common.Framework, *common.Vuln, bool) {
	return finger.activeProbeAll(level, sender)
}
