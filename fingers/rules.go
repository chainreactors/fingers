package fingers

import (
	"bytes"
	"regexp"
	"strings"

	"github.com/chainreactors/fingers/common"
	"github.com/chainreactors/utils/encode"
)

type Regexps struct {
	Body                  []string         `yaml:"body,omitempty" json:"body,omitempty" jsonschema:"title=Body Patterns,description=String patterns to match in HTTP response body,nullable,example=<title>nginx</title>"`
	MD5                   []string         `yaml:"md5,omitempty" json:"md5,omitempty" jsonschema:"title=MD5 Hashes,description=MD5 hashes of response bodies to match,nullable,pattern=^[a-f0-9]{32}$,example=d41d8cd98f00b204e9800998ecf8427e"`
	MMH3                  []string         `yaml:"mmh3,omitempty" json:"mmh3,omitempty" jsonschema:"title=MMH3 Hashes,description=MurmurHash3 hashes for favicon matching,nullable,example=116323821"`
	Regexp                []string         `yaml:"regexp,omitempty" json:"regexp,omitempty" jsonschema:"title=Regular Expressions,description=Regex patterns for advanced matching,nullable,example=nginx/([\\d\\.]+)"`
	Version               []string         `yaml:"version,omitempty" json:"version,omitempty" jsonschema:"title=Version Patterns,description=Regex patterns to extract version information,nullable,example=([\\d\\.]+)"`
	Cert                  []string         `yaml:"cert,omitempty" json:"cert,omitempty" jsonschema:"title=Certificate Patterns,description=Patterns to match in SSL certificates,nullable,example=nginx"`
	CompliedRegexp        []*regexp.Regexp `yaml:"-" json:"-"`
	CompiledVulnRegexp    []*regexp.Regexp `yaml:"-" json:"-"`
	CompiledVersionRegexp []*regexp.Regexp `yaml:"-" json:"-"`
	FingerName            string           `yaml:"-" json:"-"`
	Header                []string         `yaml:"header,omitempty" json:"header,omitempty" jsonschema:"title=Header Patterns,description=Patterns to match in HTTP headers,nullable,example=Server: nginx"`
	Vuln                  []string         `yaml:"vuln,omitempty" json:"vuln,omitempty" jsonschema:"title=Vulnerability Patterns,description=Regex patterns indicating security vulnerabilities,nullable,example=admin/config.php"`
}

func (r *Regexps) Compile(caseSensitive bool) error {
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
		if !caseSensitive {
			r.Body[i] = strings.ToLower(b)
		}
	}

	for i, h := range r.Header {
		if !caseSensitive {
			r.Header[i] = strings.ToLower(h)
		}
	}
	return nil
}

type Favicons struct {
	Mmh3 []string `yaml:"mmh3,omitempty" json:"mmh3,omitempty" jsonschema:"title=MMH3 Hashes,description=MurmurHash3 hashes of favicon content,nullable,example=116323821"`
	Md5  []string `yaml:"md5,omitempty" json:"md5,omitempty" jsonschema:"title=MD5 Hashes,description=MD5 hashes of favicon content,nullable,pattern=^[a-f0-9]{32}$,example=d41d8cd98f00b204e9800998ecf8427e"`
}

type Rule struct {
	Version     string    `yaml:"version,omitempty" json:"version,omitempty" jsonschema:"title=Version,description=Version string or extraction pattern,nullable,example=1.18.0"`
	Favicon     *Favicons `yaml:"favicon,omitempty" json:"favicon,omitempty" jsonschema:"title=Favicon Rules,description=Favicon-based matching rules,nullable"`
	Regexps     *Regexps  `yaml:"regexps,omitempty" json:"regexps,omitempty" jsonschema:"title=Regex Rules,description=Regular expression matching rules,nullable"`
	SendDataStr string    `yaml:"send_data,omitempty" json:"send_data,omitempty" jsonschema:"title=Send Data,description=Data to send for active probing,nullable,example=GET /admin HTTP/1.1\\r\\nHost: {{Hostname}}\\r\\n\\r\\n"`
	SendData    senddata  `yaml:"-" json:"-"`
	Info        string    `yaml:"info,omitempty" json:"info,omitempty" jsonschema:"title=Information,description=Additional information about the detection,nullable,example=Admin panel detected"`
	Vuln        string    `yaml:"vuln,omitempty" json:"vuln,omitempty" jsonschema:"title=Vulnerability,description=Vulnerability information if detected,nullable,example=Default admin credentials"`
	Level       int       `yaml:"level,omitempty" json:"level,omitempty" jsonschema:"title=Detection Level,description=Active probing level (0=passive 1+=active),minimum=0,maximum=5,default=0,example=1"`
	FingerName  string    `yaml:"-" json:"-"`
	IsActive    bool      `yaml:"-" json:"-"`
}

func (r *Rule) Compile(name string, caseSensitive bool) error {
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
		err := r.Regexps.Compile(caseSensitive)
		if err != nil {
			return err
		}
	}

	return nil
}

// ActiveSendDataList selects the active probing payloads based on level:
// level 0: passive only (no sender)
// level 1: finger-level send_data
// level 2+: finger-level send_data AND rule-level send_data
func (r *Rule) ActiveSendDataList(level int, fingerSendData senddata) []senddata {
	if level <= 0 {
		return nil
	}
	if r.Level > 0 && level < r.Level {
		return nil
	}

	var payloads []senddata
	if level >= 1 && !fingerSendData.IsNull() {
		payloads = append(payloads, fingerSendData)
	}
	if level >= 2 && !r.SendData.IsNull() {
		payloads = append(payloads, r.SendData)
	}
	return payloads
}

// ActiveSendData returns the most specific payload for backward compatibility.
func (r *Rule) ActiveSendData(level int, fingerSendData senddata) (senddata, bool) {
	payloads := r.ActiveSendDataList(level, fingerSendData)
	if len(payloads) == 0 {
		return nil, false
	}
	return payloads[len(payloads)-1], true
}

// ActiveSendDataStr returns the most specific active probing payload string.
func (r *Rule) ActiveSendDataStr(fingerSendDataStr string) string {
	if r.SendDataStr != "" {
		return r.SendDataStr
	}
	return fingerSendDataStr
}

// RefreshActive recomputes whether the rule is active based on send_data presence.
func (r *Rule) RefreshActive() {
	r.IsActive = r.SendDataStr != ""
}

type Rules []*Rule

func (rs Rules) Compile(name string, caseSensitive bool) error {
	for _, r := range rs {
		err := r.Compile(name, caseSensitive)
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *Rule) Match(content, header, body []byte) (bool, bool, string, *common.MatchDetail) {
	newDetail := func(matcherType string, matcherIndex int, matcherValue string) *common.MatchDetail {
		return &common.MatchDetail{
			MatcherType:  matcherType,
			MatcherIndex: matcherIndex,
			MatcherValue: matcherValue,
		}
	}
	// 漏洞匹配优先
	for i, reg := range r.Regexps.CompiledVulnRegexp {
		res, ok := compiledMatch(reg, content)
		if ok {
			return true, true, res, newDetail("regexp_vuln", i, reg.String())
		}
	}

	// 正则匹配
	for i, reg := range r.Regexps.CompliedRegexp {
		res, ok := compiledMatch(reg, content)
		if ok {
			FingerLog.Debugf("%s finger hit, regexp: %q", r.FingerName, reg.String())
			return true, false, res, newDetail("regexp", i, reg.String())
		}
	}

	// http头匹配, http协议特有的匹配
	if header != nil {
		for i, headerStr := range r.Regexps.Header {
			if bytes.Contains(header, []byte(headerStr)) {
				FingerLog.Debugf("%s finger hit, header: %s", r.FingerName, headerStr)
				return true, false, "", newDetail("header", i, headerStr)
			}
		}
	}

	if body == nil && header == nil {
		body = content
	}

	// body匹配
	for i, bodyReg := range r.Regexps.Body {
		if bytes.Contains(body, []byte(bodyReg)) {
			FingerLog.Debugf("%s finger hit, body: %q", r.FingerName, bodyReg)
			return true, false, "", newDetail("body", i, bodyReg)
		}
	}

	// MD5 匹配
	for i, md5s := range r.Regexps.MD5 {
		if md5s == encode.Md5Hash(body) {
			FingerLog.Debugf("%s finger hit, md5: %s", r.FingerName, md5s)
			return true, false, "", newDetail("md5", i, md5s)
		}
	}

	// mmh3 匹配
	for i, mmh3s := range r.Regexps.MMH3 {
		if mmh3s == encode.Mmh3Hash32(body) {
			FingerLog.Debugf("%s finger hit, mmh3: %s", r.FingerName, mmh3s)
			return true, false, "", newDetail("mmh3", i, mmh3s)
		}
	}

	return false, false, "", nil
}

func (r *Rule) MatchCert(content string) bool {
	for _, cert := range r.Regexps.Cert {
		if strings.Contains(content, cert) {
			return true
		}
	}
	return false
}
