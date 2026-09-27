package judge

import (
	"context"
	"fmt"
	"strconv"

	"github.com/chainreactors/fingers/common"
	"github.com/chainreactors/fingers/judge/internal/evidence"
	"github.com/chainreactors/utils/jev"
)

// Presence options, as written to Framework.Judge.Option: the option a
// presence claim was ruled with. Declared and absent are rulings code makes
// from the response head; the rest are the provider's.
const (
	OptionDeclared  = "declared"  // holds: the response names the product in an explicit header declaration, or shows the protocol feature
	OptionAbsent    = "absent"    // refuted: a protocol feature the response head does not show
	OptionRunning   = "running"   // holds: the evidence shows the product produced the response
	OptionMentioned = "mentioned" // refuted: the product only appears in the page's content
	OptionUnrelated = "unrelated" // refuted: the rule matched text that has nothing to do with the product
)

// matchExcerpt is one excerpt of the response a claim rests on, as the provider
// reads it.
type matchExcerpt struct {
	Where   string `json:"where"`             // "header" or "body"
	Matched string `json:"matched,omitempty"` // the text the rule matched, when the engine records it
	Text    string `json:"text"`              // the matched text with its context
}

func (e matchExcerpt) String() string {
	if e.Matched != "" {
		return e.Where + " (matched " + strconv.Quote(e.Matched) + "): " + e.Text
	}
	return e.Where + ": " + e.Text
}

// presenceClaim is a rule's claim that name is part of the software stack
// that produced the response; state.matches[id] quotes where it matched.
func presenceClaim(id, name string) jev.Claim {
	return jev.Claim{
		Statement: fmt.Sprintf("`matches.%s` contains evidence for the fingerprint rule's claim that `%s` is part of the software stack "+
			"that produced this HTTP response; it quotes the response where the rule matched: `matched` is the text "+
			"the rule matched, `text` that text in its context; evidence without `matched` is where the product's name occurs. "+
			"Judge the claim from the evidence and the response. On documentation, README or tutorial pages the documented "+
			"product is mentioned, not running; the documentation generator is running.", id, name),
		Options: map[string]jev.Option{
			OptionRunning: {Description: "`" + name + "` served, generated or is loaded by this response: headers, cookies, asset paths, markup, " +
				"or the stock text of its own login, console, default or error page. A packaged browser-side application counts.", Outcome: jev.Holds},
			OptionMentioned: {Description: "`" + name + "` only appears in content: an article, README, documentation, link or list.", Outcome: jev.Refuted},
			OptionUnrelated: {Description: "The matched text has nothing to do with `" + name + "`: it is a fragment of encoded or random data, " +
				"part of another word, or another product's asset.", Outcome: jev.Refuted},
			jev.OptionInsufficient: {Description: "The evidence shows neither.", Outcome: jev.Insufficient},
		},
	}
}

// presence applies local facts and asks one batch for the remaining products.
func (j *Judge) presence(ctx context.Context, p *evidence.Page, frames common.Frameworks) error {
	claims := map[string]jev.Claim{}
	targets := map[string][]*common.Framework{}
	matches := map[string][]matchExcerpt{}
	for _, group := range groupProducts(frames) {
		name := group[0].Name
		for _, f := range group[1:] {
			f.Judge = &common.Judgement{Duplicate: true}
		}
		key := NormalizeName(name)
		excerpts := evidenceFor(p.Raw, group)
		option := ""
		if protocolFeatures[key] {
			option = OptionAbsent
			if protocolPresent(p, key) {
				option = OptionDeclared
			}
		} else if declares(p, name) {
			option = OptionDeclared
		}
		if option != "" {
			claim := jev.Claim{Statement: "The response declares " + name, Options: map[string]jev.Option{
				OptionDeclared:         {Description: "Explicit product declaration or protocol feature", Outcome: jev.Holds},
				OptionAbsent:           {Description: "The protocol feature is absent", Outcome: jev.Refuted},
				jev.OptionInsufficient: {Description: insufficientDescription, Outcome: jev.Insufficient},
			}}
			if err := j.applyPresence(group, excerpts, claim, jev.Ruling{Option: option, Confidence: 1}); err != nil {
				return err
			}
			continue
		}
		if len(claims) >= maxClaims {
			continue
		}
		id := "presence_" + key
		claims[id], targets[id], matches[id] = presenceClaim(id, name), group, excerpts
	}
	rulings, err := j.judge(ctx, map[string]interface{}{"response": p, "matches": matches}, claims)
	if err != nil {
		return err
	}
	for id, ruling := range rulings {
		if err := j.applyPresence(targets[id], matches[id], claims[id], ruling); err != nil {
			return err
		}
	}
	return nil
}

func (j *Judge) rejects(o jev.Outcome) bool {
	return o == jev.Refuted || (o == jev.Insufficient && j.DropInsufficient)
}

// applyPresence is shared by deterministic and provider presence rulings.
func (j *Judge) applyPresence(frames []*common.Framework, evidence []matchExcerpt, claim jev.Claim, ruling jev.Ruling) error {
	if err := validRuling(claim, ruling); err != nil {
		return err
	}
	outcome := claim.Resolve(ruling, j.MinConfidence)
	var excerpts []string
	for _, e := range evidence {
		excerpts = append(excerpts, e.String())
	}
	for i, f := range frames {
		f.Judge = &common.Judgement{Option: ruling.Option, Outcome: outcome.String(),
			Evidence: append([]string(nil), excerpts...), Confidence: ruling.Confidence,
			Rejected: j.rejects(outcome), Duplicate: i > 0}
	}
	return nil
}
