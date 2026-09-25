package fingers

import (
	"context"
	"errors"

	"github.com/chainreactors/fingers/common"
	"github.com/chainreactors/fingers/judge"
)

var ErrNoJudge = errors.New("no judge attached, call AttachJudge first")

// AttachJudge adds a judgement layer (see package judge) on top of the
// enabled engines, e.g. engine.AttachJudge(jev.NewJudge("")). The rule
// engines are untouched: WebMatch/DetectContent stay synchronous and
// offline; Refine judges their result afterwards, typically asynchronously.
// Every alias name becomes a recall candidate for false negatives.
func (engine *Engine) AttachJudge(j *judge.Judge) {
	var names []string
	if engine.Aliases != nil {
		for name := range engine.Aliases.Aliases {
			names = append(names, name)
		}
	}
	engine.judge, engine.recall = j, judge.NewRetriever(names)
}

// Refine judges frames, the rule result for the raw HTTP response content,
// and marks them in place (read with judge.Is, judge.LayerOf,
// judge.Accepted); fingerprint names found in the page but missed by the
// rules are recall candidates. The returned page carries the page kind.
// Refine writes to frames: do not read them concurrently. On error, frames
// hold the rule result.
func (engine *Engine) Refine(ctx context.Context, content []byte, frames common.Frameworks) (*judge.Page, error) {
	if engine.judge == nil {
		return nil, ErrNoJudge
	}
	page, err := judge.NewPage(content)
	if err != nil {
		return nil, err
	}
	return page, judge.Refine(ctx, engine.judge, page, frames, engine.recall.Find(page.Haystack(), 24))
}
