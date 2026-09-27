// Package judge reviews fingerprint rule results with jev claims
// (github.com/chainreactors/utils/jev): whether each hit's product produced
// the response, and which version the response states. It never identifies
// products itself. Deterministic facts use the same claims. Duplicate
// grouping is bookkeeping.
//
//	j := judge.New(jev.Cached(client, jev.DefaultCacheSize))
//	all, err := j.Inspect(ctx, raw, hits)
//	accepted := all.Accepted()
//
// Inspect returns all annotated hits after at most two provider batches. Inputs
// are copied; errors preserve established facts and leave untouched claims
// unjudged. A low-confidence ruling resolves to Insufficient without
// rewriting the selected option.
//
// Offline audit and clustering live in judge/maintain, fingerprint
// generation in judge/gen.
package judge
