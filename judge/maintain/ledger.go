// Package maintain audits a fingerprint library offline from judged scan
// results. Ledger asks the provider nothing new: a rule whose presence
// claims are refuted again and again is a junk rule. Discover clusters one
// page served by several hosts and asks one coverage claim per cluster; a
// refuted one is a missed product, named by a person from code's
// candidates and turned into rules by judge/gen.
package maintain

import (
	"sort"
	"sync"

	"github.com/chainreactors/fingers/common"
	"github.com/chainreactors/utils/jev"
)

// RuleKey identifies the rule behind a hit as precisely as the engine
// reports it: engines that record MatchDetail (the native fingers engine)
// down to the matcher, the others by fingerprint name.
type RuleKey struct {
	Engine  string `json:"engine"`
	Name    string `json:"name"`
	Rule    int    `json:"rule,omitempty"`
	Matcher string `json:"matcher,omitempty"`
}

// RuleStats are the rulings on the presence claims of one rule's hits.
type RuleStats struct {
	RuleKey
	Outcomes map[jev.Outcome]int      `json:"outcomes"` // holds, refuted, insufficient
	Options  map[string]int           `json:"options"`  // the options behind them
	Samples  map[jev.Outcome][]string `json:"samples"`  // outcome -> page ids, up to maxSamples
}

const maxSamples = 5

func (s *RuleStats) Hits() int {
	total := 0
	for _, count := range s.Outcomes {
		total += count
	}
	return total
}

// RefutedFraction is the share of judged hits whose presence claim is refuted.
func (s *RuleStats) RefutedFraction() float64 {
	if s.Hits() == 0 {
		return 0
	}
	return float64(s.Outcomes[jev.Refuted]) / float64(s.Hits())
}

// Ledger accumulates rulings per rule over a scan or corpus. It is safe
// for concurrent use.
type Ledger struct {
	mu    sync.Mutex
	rules map[RuleKey]*RuleStats
}

func NewLedger() *Ledger { return &Ledger{rules: map[RuleKey]*RuleStats{}} }

// Add records the rulings of one page's Inspect result. Unjudged hits are
// skipped; duplicate spellings count for their own rule with the ruling of
// the product they spell.
func (l *Ledger) Add(page string, inspected common.Frameworks) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, f := range inspected {
		if f == nil || f.Judge == nil || f.Judge.Outcome == "" {
			continue
		}
		o := jev.Outcome(f.Judge.Outcome)
		for _, key := range ruleKeys(f) {
			s := l.rules[key]
			if s == nil {
				s = &RuleStats{RuleKey: key, Outcomes: map[jev.Outcome]int{}, Options: map[string]int{}, Samples: map[jev.Outcome][]string{}}
				l.rules[key] = s
			}
			s.Outcomes[o]++
			s.Options[f.Judge.Option]++
			if len(s.Samples[o]) < maxSamples {
				s.Samples[o] = append(s.Samples[o], page)
			}
		}
	}
}

// Report lists the rules with at least minHits judged hits whose refuted
// share is at least minRefuted, most refuted first: the junk rule
// candidates, each with the pages to review.
func (l *Ledger) Report(minHits int, minRefuted float64) []*RuleStats {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []*RuleStats
	for _, s := range l.rules {
		if s.Hits() >= minHits && s.RefutedFraction() >= minRefuted {
			snapshot := *s
			snapshot.Outcomes, snapshot.Options, snapshot.Samples = map[jev.Outcome]int{}, map[string]int{}, map[jev.Outcome][]string{}
			for k, v := range s.Outcomes {
				snapshot.Outcomes[k] = v
			}
			for k, v := range s.Options {
				snapshot.Options[k] = v
			}
			for k, v := range s.Samples {
				snapshot.Samples[k] = append([]string(nil), v...)
			}
			out = append(out, &snapshot)
		}
	}
	sort.Slice(out, func(a, b int) bool {
		ra, rb := out[a].Outcomes[jev.Refuted], out[b].Outcomes[jev.Refuted]
		if ra != rb {
			return ra > rb
		}
		return out[a].Name < out[b].Name
	})
	return out
}

func ruleKeys(f *common.Framework) []RuleKey {
	var engines []string
	for from := range f.Froms {
		if from >= common.FrameFromFingers {
			engines = append(engines, from.String())
		}
	}
	if len(engines) == 0 {
		engines = []string{"unknown"}
	}
	sort.Strings(engines)
	var keys []RuleKey
	for _, e := range engines {
		key := RuleKey{Engine: e, Name: f.Name}
		if d := f.MatchDetail; d != nil && e == common.FrameFromFingers.String() {
			key.Rule, key.Matcher = d.RuleIndex, d.MatcherValue
		}
		keys = append(keys, key)
	}
	return keys
}
