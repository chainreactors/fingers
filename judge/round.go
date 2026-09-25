package judge

import (
	"context"
	"encoding/json"
	"fmt"
)

// round is the judge primitive: questions about one page, each with a
// callback, sent as a single request. Capabilities (verifyRound,
// classifyRound, versionRound) add to a round. Callbacks run only after the
// whole request succeeded, so a failed round leaves every annotated value
// untouched.
type round struct {
	page      *Page
	questions map[string]Question
	apply     map[string]func(Answer)
	evidence  map[string]interface{}
	done      []func()
	judge     *Judge // set by ask, for thresholds in callbacks
	err       error
}

func newRound(p *Page) *round {
	return &round{page: p, questions: map[string]Question{}, apply: map[string]func(Answer){}}
}

// add asks q under key; apply receives its answer. Keys must be unique in a round.
func (r *round) add(key string, q Question, apply func(Answer)) {
	if _, dup := r.questions[key]; dup && r.err == nil {
		r.err = fmt.Errorf("judge: duplicate question key %q", key)
	}
	r.questions[key] = q
	r.apply[key] = apply
}

// then registers f to run after every answer callback, in registration
// order: for decisions that combine several answers.
func (r *round) then(f func()) { r.done = append(r.done, f) }

// show gives the provider a named piece of evidence besides the page; the
// state becomes {"response": page, name: value}. Providers read literally:
// evidence they are asked about by name weighs more than the same text in
// option descriptions.
func (r *round) show(name string, value interface{}) {
	if r.evidence == nil {
		r.evidence = map[string]interface{}{}
	}
	r.evidence[name] = value
}

// ask sends the round; a round without questions sends nothing.
func (r *round) ask(ctx context.Context, j *Judge) error {
	if r.err != nil {
		return r.err
	}
	if len(r.questions) == 0 {
		return nil
	}
	var state interface{} = r.page
	if len(r.evidence) > 0 {
		m := map[string]interface{}{"response": r.page}
		for k, v := range r.evidence {
			m[k] = v
		}
		state = m
	}
	// Answers are cached per question: the page matches by signature (similar
	// pages share answers) plus its title, named evidence exactly.
	scope, err := json.Marshal([]interface{}{r.page.similarityScope(), r.evidence})
	if err != nil {
		return err
	}
	answers, err := j.ask(ctx, state, r.questions, scope, r.page.signature())
	if err != nil {
		return err
	}
	r.judge = j
	for key, apply := range r.apply {
		if a, ok := answers[key]; ok && apply != nil {
			apply(a)
		}
	}
	for _, f := range r.done {
		f()
	}
	return nil
}
