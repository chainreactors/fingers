package judge

import (
	"context"
	"sort"

	"github.com/chainreactors/fingers/common"
	"github.com/chainreactors/fingers/judge/internal/evidence"
	"github.com/chainreactors/utils/jev"
)

// Inspect evaluates presence and versions once and returns every annotated hit.
// Call Accepted on the result to obtain the reporting view. Inputs are never changed.
// On error, the copied baseline and all facts established so far remain available;
// unjudged claims have no outcome. Each provider batch is validated before application.
func (j *Judge) Inspect(ctx context.Context, raw []byte, hits common.Frameworks) (common.Frameworks, error) {
	working := cloneFrameworks(hits)
	for _, f := range working {
		if f != nil {
			f.Judge = nil
		}
	}
	if err := j.ready(ctx); err != nil {
		return working, err
	}
	p, err := evidence.NewPage(raw)
	if err != nil {
		return working, err
	}
	if err := j.presence(ctx, p, working); err != nil {
		return working, err
	}
	return working, j.versions(ctx, p, versionOrder(working.Accepted())...)
}

// Version selects one extracted version using the same claims as Inspect.
func (j *Judge) Version(ctx context.Context, raw []byte, f *common.Framework) (string, error) {
	if f == nil {
		return "", nil
	}
	if err := j.ready(ctx); err != nil {
		return "", err
	}
	if f.Attributes != nil && f.Version != "" {
		return f.Version, nil
	}
	p, err := evidence.NewPage(raw)
	if err != nil {
		return "", err
	}
	copied := cloneFramework(f)
	err = j.versions(ctx, p, copied)
	if copied.Attributes == nil {
		return "", err
	}
	return copied.Version, err
}

// versionOrder is the order products are versioned in, as maxVersioned caps
// them: confirmed products first, then undecided, then unjudged, by name.
func versionOrder(frames common.Frameworks) []*common.Framework {
	rank := func(f *common.Framework) int {
		switch {
		case f.Judge == nil:
			return 2
		case f.Judge.Outcome == jev.Holds.String():
			return 0
		}
		return 1
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
		judgement.Evidence = append([]string(nil), f.Judge.Evidence...)
		copy.Judge = &judgement
	}
	if f.MatchDetail != nil {
		detail := *f.MatchDetail
		copy.MatchDetail = &detail
	}
	return &copy
}
