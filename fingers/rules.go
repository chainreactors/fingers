package fingers

import (
	"bytes"
	"github.com/chainreactors/utils/encode"
	"regexp"
	"strings"
)

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
	if header != nil {
		for _, headerStr := range r.Regexps.Header {
			if bytes.Contains(header, []byte(headerStr)) {
				FingerLog.Debugf("%s finger hit, header: %s", r.FingerName, headerStr)
				return true, false, ""
			}
		}
	}

	if body == nil && header == nil {
		body = content
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
