package fingers

import (
	"regexp"
	"strings"

	"github.com/chainreactors/fingers/common"
)

func compileRegexp(s string) (*regexp.Regexp, error) {
	reg, err := regexp.Compile(s)
	if err != nil {
		return nil, err
	}
	return reg, nil
}

func compiledMatch(reg *regexp.Regexp, s []byte) (string, bool) {
	matched := reg.FindSubmatch(s)
	if matched == nil {
		return "", false
	}
	if len(matched) == 1 {
		return "", true
	} else {
		return strings.TrimSpace(string(matched[1])), true
	}
}

func compiledAllMatch(reg *regexp.Regexp, s string) ([]string, bool) {
	matchedes := reg.FindAllString(s, -1)
	if matchedes == nil {
		return nil, false
	}
	return matchedes, true
}

func RuleMatcher(rule *Rule, content *Content, ishttp bool) (bool, bool, string, *common.MatchDetail) {
	var hasFrame, hasVuln bool
	var version string
	var detail *common.MatchDetail
	if rule.Regexps == nil {
		return false, false, "", nil
	}

	hasFrame, hasVuln, version, detail = rule.Match(content.Content, content.Header, content.Body)
	if hasFrame || !ishttp {
		return hasFrame, hasVuln, version, detail
	}

	if content.Cert != "" {
		hasFrame = rule.MatchCert(content.Cert)
		if hasFrame && detail == nil {
			detail = &common.MatchDetail{MatcherType: "cert"}
		}
	}

	if version == "" && rule.Regexps.CompiledVersionRegexp != nil {
		for _, reg := range rule.Regexps.CompiledVersionRegexp {
			version, _ = compiledMatch(reg, content.Content)
		}
	}
	return hasFrame, hasVuln, version, detail
}
