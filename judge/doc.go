// Package judge exposes evidence-based judgement operations for HTTP
// fingerprints. A Provider (such as TypeSafe Jev in judge/jev) answers typed
// questions; Judge applies thresholds, caching and fingerprint semantics.
//
//	j := judge.New(provider)
//	accepted, kind, generic, err := j.Refine(ctx, raw, ruleHits)
//	all, err := j.Inspect(ctx, raw, ruleHits) // includes rejected hits
//	finger, err := judge.NewGenerator(j).Positive(good).Negative(other).Generate(ctx)
//
// Judge methods do not mutate rule hits. Round remains available for callers
// composing custom questions into one provider request. Similar pages can
// share cached answers through Page.Signature.
//
// See README.md in this directory.
package judge
