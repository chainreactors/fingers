// Package judge is the judgement and rerank layer of fingers. It sits on top
// of the rule engines instead of being one: rules and code recall candidates
// with evidence, a Provider (a model such as TypeSafe Jev in judge/jev)
// answers typed questions about that evidence, and code makes every final
// decision.
//
//	j := judge.New(provider)                 // shared by a whole scan: cache, merging, thresholds
//	page, _ := judge.NewPage(raw)            // page data entry
//	r := page.Round()                        // one request
//	judge.Verify(r, frames, recall)          // false positives / negatives, duplicates, layer, primary
//	judge.Classify(r)                        // page kind, generic page
//	err := r.Ask(ctx, j)                     // answers mark frames and page in place
//	r = page.Round()
//	judge.Version(r, judge.PrimaryOf(frames)) // version of the primary application
//	err = r.Ask(ctx, j)
//
// Refine runs exactly this; fingers.Engine.Refine adds recall from the
// fingerprint names. Results are Marks on the frameworks (Is, LayerOf,
// Accepted) and Kind / Generic on the page. Answers are cached per question,
// and similar pages (Page.Signature) share them.
//
// See README.md in this directory.
package judge
