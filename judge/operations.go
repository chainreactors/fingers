package judge

import (
	"context"
	"fmt"
	"math"

	"github.com/chainreactors/fingers/common"
)

// Yes returns the probability that the answer to question is yes. State can
// be any JSON-serializable value, including a Page returned by NewPage.
func (j *Judge) Yes(ctx context.Context, state any, question string) (float64, error) {
	answers, err := j.Ask(ctx, state, map[string]Question{"yes": Binary(question)})
	if err != nil {
		return 0, err
	}
	return answers["yes"].Yes, nil
}

// Choose selects one option and returns its confidence.
func (j *Judge) Choose(ctx context.Context, state any, question string, options map[string]string) (string, float64, error) {
	if len(options) < 2 {
		return "", 0, fmt.Errorf("judge: choose needs at least two options")
	}
	answers, err := j.Ask(ctx, state, map[string]Question{"choice": Choice(question, options)})
	if err != nil {
		return "", 0, err
	}
	a := answers["choice"]
	if _, ok := options[a.Choice]; !ok {
		return "", 0, fmt.Errorf("judge: provider chose unknown option %q", a.Choice)
	}
	return a.Choice, a.Confidence, nil
}

// Score returns a value from 0 to 1 on the ordered levels.
func (j *Judge) Score(ctx context.Context, state any, question string, levels ...string) (float64, error) {
	if len(levels) < 2 || len(levels) > 10 {
		return 0, fmt.Errorf("judge: score needs 2 to 10 levels")
	}
	answers, err := j.Ask(ctx, state, map[string]Question{"score": Score(question, levels)})
	if err != nil {
		return 0, err
	}
	score := answers["score"].Score
	if math.IsNaN(score) || score < 0 || score > 1 {
		return 0, fmt.Errorf("judge: provider returned invalid score %v", score)
	}
	return score, nil
}

// Inspect returns all rule hits with judgement marks, including rejected and
// duplicate hits. The input map and its frameworks are never changed.
func (j *Judge) Inspect(ctx context.Context, raw []byte, frames common.Frameworks, knownNames ...string) (common.Frameworks, error) {
	p, err := NewPage(raw)
	if err != nil {
		return nil, err
	}
	working := cloneFrameworks(frames)
	r := p.Round()
	Verify(r, working, knownNames)
	if err := r.Ask(ctx, j); err != nil {
		return nil, err
	}
	return working, nil
}

// Verify returns the accepted fingerprints after judging rule hits and
// optional known-name candidates. Use Inspect for rejected-hit diagnostics.
func (j *Judge) Verify(ctx context.Context, raw []byte, frames common.Frameworks, knownNames ...string) (common.Frameworks, error) {
	all, err := j.Inspect(ctx, raw, frames, knownNames...)
	if err != nil {
		return nil, err
	}
	return Accepted(all), nil
}

// Classify reports the page kind and whether it is a stock product page.
func (j *Judge) Classify(ctx context.Context, raw []byte) (Kind, bool, error) {
	p, err := NewPage(raw)
	if err != nil {
		return "", false, err
	}
	r := p.Round()
	Classify(r)
	if err := r.Ask(ctx, j); err != nil {
		return "", false, err
	}
	return p.Kind, p.Generic, nil
}

// Version selects a version for f when the response contains a supported
// version string. It does not change f.
func (j *Judge) Version(ctx context.Context, raw []byte, f *common.Framework) (string, error) {
	if f == nil {
		return "", nil
	}
	if f.Attributes != nil && f.Version != "" {
		return f.Version, nil
	}
	p, err := NewPage(raw)
	if err != nil {
		return "", err
	}
	copy := cloneFramework(f)
	r := p.Round()
	Version(r, copy)
	if err := r.Ask(ctx, j); err != nil {
		return "", err
	}
	if copy.Attributes == nil {
		return "", nil
	}
	return copy.Version, nil
}

// Refine verifies hits, classifies the page and resolves the primary product's
// version. Both rounds must succeed; input frames are never changed.
func (j *Judge) Refine(ctx context.Context, raw []byte, frames common.Frameworks, knownNames ...string) (common.Frameworks, Kind, bool, error) {
	p, err := NewPage(raw)
	if err != nil {
		return nil, "", false, err
	}
	all, err := runRefine(ctx, j, p, frames, knownNames)
	if err != nil {
		return nil, "", false, err
	}
	return Accepted(all), p.Kind, p.Generic, nil
}
