package fingers

import (
	"sort"

	"github.com/chainreactors/utils/ahocorasick"
)

type keywordRef struct {
	FingerIdx  int
	RuleIdx    int
	PatternIdx int
}

type KeywordIndex struct {
	bodyAC     *ahocorasick.Automaton
	headerAC   *ahocorasick.Automaton
	bodyRefs   []keywordRef
	headerRefs []keywordRef

	nonKeywordFingerIdxs []int
}

func NewKeywordIndex(fingers Fingers) *KeywordIndex {
	idx := &KeywordIndex{}

	var bodyKeywords []string
	var headerKeywords []string
	nonKeyword := make(map[int]bool)

	for fi, finger := range fingers {
		for _, rule := range finger.Rules {
			if rule.Regexps == nil {
				continue
			}

			for pi, body := range rule.Regexps.Body {
				bodyKeywords = append(bodyKeywords, body)
				idx.bodyRefs = append(idx.bodyRefs, keywordRef{fi, 0, pi})
			}

			for pi, header := range rule.Regexps.Header {
				headerKeywords = append(headerKeywords, header)
				idx.headerRefs = append(idx.headerRefs, keywordRef{fi, 0, pi})
			}

			if len(rule.Regexps.CompliedRegexp) > 0 || len(rule.Regexps.CompiledVulnRegexp) > 0 ||
				len(rule.Regexps.MD5) > 0 || len(rule.Regexps.MMH3) > 0 || len(rule.Regexps.Cert) > 0 {
				nonKeyword[fi] = true
			}
		}
	}

	if len(bodyKeywords) > 0 {
		ac, err := ahocorasick.NewBuilder().
			AddStrings(bodyKeywords).
			Build()
		if err == nil {
			idx.bodyAC = ac
		}
	}

	if len(headerKeywords) > 0 {
		ac, err := ahocorasick.NewBuilder().
			AddStrings(headerKeywords).
			Build()
		if err == nil {
			idx.headerAC = ac
		}
	}

	for fi := range nonKeyword {
		idx.nonKeywordFingerIdxs = append(idx.nonKeywordFingerIdxs, fi)
	}
	sort.Ints(idx.nonKeywordFingerIdxs)

	return idx
}

func (idx *KeywordIndex) MatchCandidates(header, body []byte) map[int]bool {
	candidates := make(map[int]bool)

	if idx.headerAC != nil && len(header) > 0 {
		matches := idx.headerAC.FindAll(header, -1)
		for _, m := range matches {
			ref := idx.headerRefs[m.PatternID]
			candidates[ref.FingerIdx] = true
		}
	}

	if idx.bodyAC != nil && len(body) > 0 {
		matches := idx.bodyAC.FindAll(body, -1)
		for _, m := range matches {
			ref := idx.bodyRefs[m.PatternID]
			candidates[ref.FingerIdx] = true
		}
	}

	for _, fi := range idx.nonKeywordFingerIdxs {
		candidates[fi] = true
	}

	return candidates
}
