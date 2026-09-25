package jev

import (
	"context"

	"github.com/chainreactors/fingers/common"
)

// Refine is the default pipeline: Verify and Classify in one request, then
// the version of the page's subject in a second one. frames and p are
// annotated in place; on error the second round's annotations are missing,
// the first round's are complete or absent.
func Refine(ctx context.Context, c *Client, p *Page, frames common.Frameworks, recall []string) error {
	r := p.Round()
	Verify(r, frames, recall)
	Classify(r)
	if err := r.Ask(ctx, c); err != nil {
		return err
	}
	r = p.Round()
	Version(r, subject(frames))
	return r.Ask(ctx, c)
}

// subject is the product whose version the page most likely shows: the
// primary application, or on pages without one (a server's default or error
// page) the only accepted server, application or device.
func subject(frames common.Frameworks) *common.Framework {
	if f := Primary(frames); f != nil {
		return f
	}
	var only *common.Framework
	for _, f := range Accepted(frames) {
		for _, l := range []Layer{LayerServer, LayerApplication, LayerDevice} {
			if f.HasTag(TagLayer + string(l)) {
				if only != nil {
					return nil
				}
				only = f
			}
		}
	}
	return only
}

// Primary returns the framework Verify tagged as the page's application.
func Primary(frames common.Frameworks) *common.Framework {
	for _, f := range frames {
		if f.HasTag(TagPrimary) {
			return f
		}
	}
	return nil
}

// Accepted returns frames without rejected hits and duplicate spellings.
func Accepted(frames common.Frameworks) common.Frameworks {
	out := common.Frameworks{}
	for k, f := range frames {
		if !f.HasTag(TagRejected) && !f.HasTag(TagDup) {
			out[k] = f
		}
	}
	return out
}
