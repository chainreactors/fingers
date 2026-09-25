package judge

import (
	"context"

	"github.com/chainreactors/fingers/common"
)

// refine keeps the first round's output private until version resolution ends.
func runRefine(ctx context.Context, j *Judge, p *Page, frames common.Frameworks, recall []string) (common.Frameworks, error) {
	working := cloneFrameworks(frames)
	page := *p
	r := page.Round()
	Verify(r, working, recall)
	Classify(r)
	if err := r.Ask(ctx, j); err != nil {
		return nil, err
	}
	r = page.Round()
	Version(r, subject(working))
	if err := r.Ask(ctx, j); err != nil {
		return nil, err
	}
	p.Kind, p.Generic = page.Kind, page.Generic
	return working, nil
}

func cloneFrameworks(frames common.Frameworks) common.Frameworks {
	working := make(common.Frameworks, len(frames))
	for name, f := range frames {
		working[name] = cloneFramework(f)
	}
	return working
}

func cloneFramework(f *common.Framework) *common.Framework {
	if f == nil {
		return nil
	}
	copy := *f
	copy.Tags = append([]string(nil), f.Tags...)
	if f.Froms != nil {
		copy.Froms = make(map[common.From]bool, len(f.Froms))
		for from, present := range f.Froms {
			copy.Froms[from] = present
		}
	}
	if f.Attributes != nil {
		attrs := *f.Attributes
		copy.Attributes = &attrs
	}
	return &copy
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
