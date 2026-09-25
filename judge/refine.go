package judge

import (
	"context"
	"sort"

	"github.com/chainreactors/fingers/common"
)

// inspect judges a copy of frames plus the known names found in the page.
// When the Judge caches answers, the page is classified in the same request,
// so a later Classify of this response costs nothing.
func (j *Judge) inspect(ctx context.Context, p *Page, frames common.Frameworks) (common.Frameworks, error) {
	working := cloneFrameworks(frames)
	r := newRound(p)
	verifyRound(r, working, j.known(p))
	if j.Cache != nil {
		var kind Kind
		var generic bool
		classifyRound(r, &kind, &generic)
	}
	if err := r.ask(ctx, j); err != nil {
		return nil, err
	}
	return working, nil
}

func (j *Judge) known(p *Page) []string {
	if j.Known == nil {
		return nil
	}
	return j.Known.Find(p.haystack(), maxKnown)
}

// byImportance orders frames for versioning: the primary application first,
// then applications, servers and the rest, each by name.
func byImportance(frames common.Frameworks) []*common.Framework {
	rank := func(f *common.Framework) int {
		switch {
		case f.Judge == nil:
			return 3
		case f.Judge.Primary:
			return 0
		case f.Judge.Layer == LayerApplication || f.Judge.Layer == LayerDevice:
			return 1
		case f.Judge.Layer == LayerFrontend:
			return 3
		}
		return 2
	}
	list := frames.List()
	sort.Slice(list, func(a, b int) bool {
		if ra, rb := rank(list[a]), rank(list[b]); ra != rb {
			return ra < rb
		}
		return list[a].Name < list[b].Name
	})
	return list
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
	if f.Judge != nil {
		judgement := *f.Judge
		copy.Judge = &judgement
	}
	return &copy
}
