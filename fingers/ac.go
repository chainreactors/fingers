package fingers

import (
	"github.com/chainreactors/utils/ahocorasick"
)

type KeywordIndex struct {
	dual     *ahocorasick.DualKeywordIndex
	fastPath map[int]bool // finger indices that can be resolved by AC hit alone
}

func NewKeywordIndex(fingers Fingers) *KeywordIndex {
	builder := ahocorasick.NewDualKeywordIndexBuilder()
	fastPath := make(map[int]bool)

	for fi, finger := range fingers {
		isFast := isSimpleFinger(finger)

		for _, rule := range finger.Rules {
			if rule.Regexps == nil {
				continue
			}

			for _, body := range rule.Regexps.Body {
				builder.AddBodyKeyword(body, fi)
			}
			for _, header := range rule.Regexps.Header {
				builder.AddHeaderKeyword(header, fi)
			}

			if len(rule.Regexps.CompliedRegexp) > 0 || len(rule.Regexps.CompiledVulnRegexp) > 0 ||
				len(rule.Regexps.MD5) > 0 || len(rule.Regexps.MMH3) > 0 || len(rule.Regexps.Cert) > 0 {
				builder.AddFallback(fi)
			}
		}

		if isFast {
			fastPath[fi] = true
		}
	}

	return &KeywordIndex{
		dual:     builder.Build(),
		fastPath: fastPath,
	}
}

// isSimpleFinger returns true when a finger can be fully resolved by an AC
// keyword hit: single rule, only body/header substring matchers, no regex,
// no hash, no cert, no vuln patterns.
func isSimpleFinger(finger *Finger) bool {
	if len(finger.Rules) != 1 {
		return false
	}
	rule := finger.Rules[0]
	if rule.Regexps == nil {
		return false
	}
	r := rule.Regexps
	if len(r.CompliedRegexp) > 0 || len(r.CompiledVulnRegexp) > 0 ||
		len(r.CompiledVersionRegexp) > 0 ||
		len(r.MD5) > 0 || len(r.MMH3) > 0 || len(r.Cert) > 0 {
		return false
	}
	if len(r.Body) == 0 && len(r.Header) == 0 {
		return false
	}
	return true
}

func (idx *KeywordIndex) MatchCandidates(header, body []byte) map[int]bool {
	return idx.dual.MatchSources(header, body)
}

func (idx *KeywordIndex) IsFastPath(fi int) bool {
	return idx.fastPath[fi]
}
