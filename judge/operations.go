package judge

import (
	"context"
	"fmt"
	"math"

	"github.com/chainreactors/fingers/common"
)

// Yes returns the probability that the answer to question is yes. State can
// be any JSON-serializable value, including a Page returned by NewPage.
func (j *Judge) Yes(ctx context.Context, state interface{}, question string) (float64, error) {
	answers, err := j.Ask(ctx, state, map[string]Question{"yes": Binary(question)})
	if err != nil {
		return 0, err
	}
	return answers["yes"].Yes, nil
}

// Choose selects one option and returns its confidence.
func (j *Judge) Choose(ctx context.Context, state interface{}, question string, options map[string]string) (string, float64, error) {
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
func (j *Judge) Score(ctx context.Context, state interface{}, question string, levels ...string) (float64, error) {
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

// Refine is the scan-time entry point: it returns the fingerprints to report
// for a response. False positives and duplicate spellings are dropped, known
// names the rules missed are recalled (see Judge.Known) and every kept
// product without a version gets one when the response shows it. Each
// returned framework carries its verdict in Framework.Judge. hits are never
// changed; on error, use them as the rule-only result.
func (j *Judge) Refine(ctx context.Context, raw []byte, hits common.Frameworks) (common.Frameworks, error) {
	p, err := NewPage(raw)
	if err != nil {
		return nil, err
	}
	all, err := j.inspect(ctx, p, hits)
	if err != nil {
		return nil, err
	}
	accepted := all.Accepted()
	r := newRound(p)
	versionRound(r, byImportance(accepted)...)
	if err := r.ask(ctx, j); err != nil {
		return nil, err
	}
	return accepted, nil
}

// Inspect explains Refine: it returns every hit and recalled name with its
// verdict in Framework.Judge, rejected and duplicate ones included, and
// resolves no versions. hits are never changed.
func (j *Judge) Inspect(ctx context.Context, raw []byte, hits common.Frameworks) (common.Frameworks, error) {
	p, err := NewPage(raw)
	if err != nil {
		return nil, err
	}
	return j.inspect(ctx, p, hits)
}

// Classify reports the page kind and whether it is the stock page of a
// packaged product. After Refine of the same response it is answered from
// the cache.
func (j *Judge) Classify(ctx context.Context, raw []byte) (kind Kind, generic bool, err error) {
	p, err := NewPage(raw)
	if err != nil {
		return "", false, err
	}
	r := newRound(p)
	classifyRound(r, &kind, &generic)
	if err := r.ask(ctx, j); err != nil {
		return "", false, err
	}
	return kind, generic, nil
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
	r := newRound(p)
	versionRound(r, copy)
	if err := r.ask(ctx, j); err != nil {
		return "", err
	}
	if copy.Attributes == nil {
		return "", nil
	}
	return copy.Version, nil
}
