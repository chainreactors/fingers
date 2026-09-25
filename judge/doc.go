// Package judge filters and completes rule-engine results with a judgement
// provider. Code extracts candidates and decides; a Provider (such as
// TypeSafe Jev in judge/jev) only answers typed questions about the evidence.
//
//	j := judge.New(provider)
//	j.Known = judge.NewRetriever(engine.Names())
//	accepted, err := j.Refine(ctx, raw, hits) // what to report
//	all, err := j.Inspect(ctx, raw, hits)     // why: rejected and duplicate hits too
//	kind, generic, err := j.Classify(ctx, raw)
//
// Verdicts are written to Framework.Judge. Hits passed in are never changed.
// Answers are cached per question, and similar pages share them. Fingerprint
// generation from labelled responses lives in judge/gen.
//
// See README.md in this directory.
package judge
