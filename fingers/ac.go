package fingers

import (
	"github.com/chainreactors/utils/ahocorasick"
)

type KeywordIndex struct {
	dual *ahocorasick.DualKeywordIndex
}

func NewKeywordIndex(fingers Fingers) *KeywordIndex {
	builder := ahocorasick.NewDualKeywordIndexBuilder()

	for fi, finger := range fingers {
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
	}

	return &KeywordIndex{dual: builder.Build()}
}

func (idx *KeywordIndex) MatchCandidates(header, body []byte) map[int]bool {
	return idx.dual.MatchSources(header, body)
}
