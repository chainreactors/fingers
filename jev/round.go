package jev

import (
	"context"
	"encoding/json"
	"fmt"
)

// Round is the Jev primitive: questions about one page, each with a callback,
// sent as a single request. Capabilities (Verify, Classify, Version) are
// functions that add to a Round; callers may add their own questions too.
// Callbacks run only after the whole request succeeded, so a failed Round
// leaves every annotated value untouched.
type Round struct {
	page      *Page
	questions map[string]Question
	apply     map[string]func(Answer)
	evidence  map[string]interface{}
	done      []func()
	err       error
}

func (p *Page) Round() *Round {
	return &Round{page: p, questions: map[string]Question{}, apply: map[string]func(Answer){}}
}

func (r *Round) Page() *Page { return r.page }

// Add asks q under key; apply receives its answer. Keys must be unique in a Round.
func (r *Round) Add(key string, q Question, apply func(Answer)) {
	if _, dup := r.questions[key]; dup && r.err == nil {
		r.err = fmt.Errorf("jev: duplicate question key %q", key)
	}
	r.questions[key] = q
	r.apply[key] = apply
}

// Done registers f to run after every answer callback, in registration
// order: for decisions that combine several answers.
func (r *Round) Done(f func()) { r.done = append(r.done, f) }

// Evidence shows Jev a named piece of evidence besides the page; the state
// becomes {"response": page, name: value}. Jev reads literally: evidence it is
// asked about by name weighs more than the same text in option descriptions.
func (r *Round) Evidence(name string, value interface{}) {
	if r.evidence == nil {
		r.evidence = map[string]interface{}{}
	}
	r.evidence[name] = value
}

// Ask sends the round; a round without questions sends nothing.
func (r *Round) Ask(ctx context.Context, c *Client) error {
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
	// Similar pages share answers: the cache matches the page by signature,
	// everything else (questions, named evidence such as version strings) exactly.
	exact, err := json.Marshal([]interface{}{r.questions, r.evidence})
	if err != nil {
		return err
	}
	resp, err := c.ask(ctx, state, r.questions, exact, r.page.Signature())
	if err != nil {
		return err
	}
	for key, apply := range r.apply {
		if a, ok := resp.Answers[key]; ok && apply != nil {
			apply(a)
		}
	}
	for _, f := range r.done {
		f()
	}
	return nil
}
