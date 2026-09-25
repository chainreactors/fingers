package judge

import (
	"context"

	"github.com/chainreactors/fingers/common"
)

// Refine is the default pipeline: Verify and Classify in one request, then
// the version of the page's subject in a second one. frames and p are
// annotated in place; on error the second round's annotations are missing,
// the first round's are complete or absent.
func Refine(ctx context.Context, j *Judge, p *Page, frames common.Frameworks, recall []string) error {
	r := p.Round()
	Verify(r, frames, recall)
	Classify(r)
	if err := r.Ask(ctx, j); err != nil {
		return err
	}
	r = p.Round()
	Version(r, subject(frames))
	return r.Ask(ctx, j)
}

// subject is the product whose version the page most likely shows: the
// primary application or, on pages without one (a server's default, error
// or index page), the only accepted application, else the only server, else
// the only device.
func subject(frames common.Frameworks) *common.Framework {
	if f := PrimaryOf(frames); f != nil {
		return f
	}
	accepted := Accepted(frames)
	for _, l := range []Layer{LayerApplication, LayerServer, LayerDevice} {
		var only *common.Framework
		n := 0
		for _, f := range accepted {
			if LayerOf(f) == l {
				only, n = f, n+1
			}
		}
		if n == 1 {
			return only
		}
	}
	return nil
}
