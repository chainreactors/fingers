package fingers

import (
	"context"
	"errors"

	"github.com/chainreactors/fingers/common"
	"github.com/chainreactors/fingers/jev"
)

var ErrJevNotAttached = errors.New("jev is not attached, call AttachJev first")

// AttachJev adds the Jev judgement layer on top of the enabled engines. The
// rule engines are untouched: WebMatch/DetectContent stay synchronous and
// offline; Refine judges their result afterwards, typically asynchronously.
func (engine *Engine) AttachJev(client *jev.Client) {
	var names []string
	if engine.Aliases != nil {
		for name := range engine.Aliases.Aliases {
			names = append(names, name)
		}
	}
	engine.jevClient, engine.jevRecall = client, jev.NewRetriever(names)
}

// Refine judges frames, the rule result for the raw HTTP response content,
// and annotates them in place (see the jev.Tag* constants); fingerprint
// names found in the page but missed by the rules are recall candidates.
// The returned page carries the page kind. Refine writes to frames: do not
// read them concurrently. On error, frames hold the rule result.
func (engine *Engine) Refine(ctx context.Context, content []byte, frames common.Frameworks) (*jev.Page, error) {
	if engine.jevClient == nil {
		return nil, ErrJevNotAttached
	}
	page, err := jev.NewPage(content)
	if err != nil {
		return nil, err
	}
	return page, jev.Refine(ctx, engine.jevClient, page, frames, engine.jevRecall.Find(page.Haystack(), 24))
}
