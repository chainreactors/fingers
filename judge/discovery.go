package judge

import (
	"context"
	"fmt"
	"sort"

	"github.com/chainreactors/fingers/common"
	"github.com/chainreactors/fingers/judge/internal/evidence"
)

// IsUnknownProduct reports whether this looks like a reusable product page
// with no identified product. Pass the result of Refine; known
// infrastructure alone does not identify an application.
func (j *Judge) IsUnknownProduct(ctx context.Context, raw []byte, accepted common.Frameworks) (bool, error) {
	kind, generic, err := j.Classify(ctx, raw)
	if err != nil || !generic {
		return false, err
	}
	for _, f := range accepted.Accepted() {
		if f.Judge == nil {
			continue
		}
		switch f.Judge.Layer {
		case LayerApplication, LayerDevice:
			return false, nil
		case LayerServer, LayerCDN:
			if kind == KindDefault || kind == KindError || kind == KindDirListing {
				return false, nil
			}
		}
	}
	return true, nil
}

// SuggestNames returns product names supported by page evidence. Candidates
// are extracted from this response, including visible body text; no name is
// invented by the provider or drawn from an installed fingerprint catalog.
func (j *Judge) SuggestNames(ctx context.Context, raw []byte) ([]string, error) {
	p, err := NewPage(raw)
	if err != nil {
		return nil, err
	}
	candidates := pageNames(p)
	if len(candidates) == 0 {
		return nil, nil
	}
	r := newRound(p)
	prob := make([]float64, len(candidates))
	for i, name := range candidates {
		i, name := i, name
		r.add(fmt.Sprintf("name_%d", i), BinaryWith(
			fmt.Sprintf("Is `%s` the product whose own interface, login, console or default page this response shows, rather than infrastructure underneath another product, generic wording or an article mention?", name),
			name+" owns this page",
			name+" is infrastructure or merely mentioned"),
			func(a Answer) { prob[i] = a.Yes })
	}
	if err := r.ask(ctx, j); err != nil {
		return nil, err
	}
	var indices []int
	for i, v := range prob {
		if v >= j.Threshold {
			indices = append(indices, i)
		}
	}
	sort.SliceStable(indices, func(a, b int) bool { return prob[indices[a]] > prob[indices[b]] })
	out := make([]string, 0, len(indices))
	for _, i := range indices {
		out = append(out, candidates[i])
	}
	return out, nil
}

func pageNames(p *Page) []string {
	return evidence.Names(p.Generator, p.Title, p.Text, p.Headers, append(append([]string(nil), p.Scripts...), p.Styles...))
}
