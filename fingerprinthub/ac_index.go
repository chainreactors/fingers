package fingerprinthub

import (
	"strings"

	"github.com/chainreactors/neutron/operators"
	"github.com/chainreactors/utils/ahocorasick"
)

type TemplateKeywordIndex struct {
	dual     *ahocorasick.DualKeywordIndex
	fastPath map[int]bool
}

type MatchResult struct {
	Matched    map[int]bool
	NeedsCheck map[int]bool
}

func NewTemplateKeywordIndex(tmpls []*passiveTemplate) *TemplateKeywordIndex {
	builder := ahocorasick.NewDualKeywordIndexBuilder().SetOverlapping(true)
	fastPath := make(map[int]bool)

	for ti, tmpl := range tmpls {
		if len(tmpl.requests) == 0 {
			continue
		}

		hasKeyword := false
		forceNonKeyword := false
		isFastPath := true

		for _, req := range tmpl.requests {
			if len(req.Matchers) == 0 {
				continue
			}

			isAnd := req.MatchersCondition == "and"
			if isAnd {
				isFastPath = false
			}
			hasNonKeywordMatcher := false

			for _, matcher := range req.Matchers {
				if matcher.GetType() != operators.WordsMatcher {
					isFastPath = false
				} else if matcher.Condition == "and" && len(matcher.Words) > 1 {
					isFastPath = false
				}

				kws := extractMatcherKeywords(matcher)
				if len(kws) == 0 {
					hasNonKeywordMatcher = true
					if isAnd {
						break
					}
					continue
				}

				hasKeyword = true
				part := resolveMatcherPart(matcher)

				for _, kw := range kws {
					lower := strings.ToLower(kw)
					if part == "body" || part == "" || part == "all" {
						builder.AddBodyKeyword(lower, ti)
					}
					if part == "header" || part == "all_headers" || part == "all" {
						builder.AddHeaderKeyword(lower, ti)
					}
				}
			}

			if isAnd && hasNonKeywordMatcher {
				hasKeyword = false
				break
			}
			if !isAnd && hasNonKeywordMatcher {
				forceNonKeyword = true
				isFastPath = false
			}
		}

		if !hasKeyword || forceNonKeyword {
			builder.AddFallback(ti)
		}
		if hasKeyword && isFastPath {
			fastPath[ti] = true
		}
	}

	return &TemplateKeywordIndex{
		dual:     builder.Build(),
		fastPath: fastPath,
	}
}

func (idx *TemplateKeywordIndex) Match(headerStr, bodyStr string) MatchResult {
	result := MatchResult{
		Matched:    make(map[int]bool),
		NeedsCheck: make(map[int]bool),
	}

	allHits := idx.dual.MatchSources([]byte(headerStr), []byte(bodyStr))
	for ti := range allHits {
		if idx.fastPath[ti] {
			result.Matched[ti] = true
		} else {
			result.NeedsCheck[ti] = true
		}
	}

	return result
}

func extractMatcherKeywords(matcher *operators.Matcher) []string {
	switch matcher.GetType() {
	case operators.WordsMatcher:
		var kws []string
		for _, word := range matcher.Words {
			if len(word) >= 3 {
				kws = append(kws, word)
			}
		}
		return kws
	case operators.RegexMatcher:
		var kws []string
		for _, pattern := range matcher.Regex {
			lits := ahocorasick.ExtractLiterals(pattern)
			kws = append(kws, lits...)
		}
		return kws
	default:
		return nil
	}
}

func resolveMatcherPart(matcher *operators.Matcher) string {
	part := strings.ToLower(matcher.Part)
	if part == "" {
		return "body"
	}
	return part
}
