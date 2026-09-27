package main

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/chainreactors/fingers/common"
	fingerlib "github.com/chainreactors/fingers/fingers"
	"github.com/chainreactors/fingers/judge"
	"github.com/chainreactors/fingers/judge/gen"
	"gopkg.in/yaml.v3"
)

// generationResult records observations only. The manifest owns the product,
// training split and truth labels; scores and status are derived from them.
type generationResult struct {
	Name     string                       `json:"name"`
	File     string                       `json:"file,omitempty"`
	Training map[string]*common.Framework `json:"training"`
	Holdout  map[string]*common.Framework `json:"holdout"`
	Excluded []string                     `json:"excluded"`
	Error    string                       `json:"error,omitempty"`
}

func (r generationResult) assess(m *replayManifest, p generationPlan) (training, holdout stageScore, status string) {
	test, _, err := generationSplit(m, p)
	if err != nil || r.Error != "" {
		return training, holdout, "failed"
	}
	trainingComplete := len(r.Training) == len(p.Positive)+len(p.Negative)
	for _, ids := range [][]string{p.Positive, p.Negative} {
		for _, id := range ids {
			_, evaluated := r.Training[id]
			trainingComplete = trainingComplete && evaluated
		}
	}
	holdoutComplete := len(r.Holdout) == len(test)
	for _, sample := range test {
		_, evaluated := r.Holdout[sample.ID]
		holdoutComplete = holdoutComplete && evaluated
	}
	for _, s := range m.Samples {
		label, labelled := labelFor(s, p.Product)
		if !labelled {
			continue
		}
		if frame, evaluated := r.Training[s.ID]; evaluated {
			training.add(label, frame)
		}
		if frame, evaluated := r.Holdout[s.ID]; evaluated {
			holdout.add(label, frame)
		}
	}
	switch {
	case training.failed() || !trainingComplete:
		status = "failed_training"
	case holdout.failed():
		status = "failed_holdout"
	case !holdoutComplete || holdout.Detection.TP == 0 || holdout.Detection.TN == 0:
		status = "insufficient_holdout"
	default:
		status = "passed_holdout"
	}
	return
}

func generationSplit(m *replayManifest, p generationPlan) ([]replaySample, []string, error) {
	samples := map[string]replaySample{}
	for _, s := range m.Samples {
		samples[s.ID] = s
	}
	if p.Name == "" || p.Name != filepath.Base(p.Name) || strings.ContainsAny(p.Name, "/\\:") || p.Product == "" || len(p.Positive) == 0 || len(p.Negative) == 0 {
		return nil, nil, fmt.Errorf("invalid generation plan")
	}
	trainIDs, trainGroups, trainHashes := map[string]bool{}, map[string]bool{}, map[string]bool{}
	trainHosts := map[string]bool{}
	host := func(s replaySample) string {
		u, err := url.Parse(s.URL)
		if err != nil {
			return ""
		}
		return strings.ToLower(u.Hostname())
	}
	for _, set := range []struct {
		ids  []string
		want bool
	}{{p.Positive, true}, {p.Negative, false}} {
		for _, id := range set.ids {
			s, ok := samples[id]
			if !ok || trainIDs[id] {
				return nil, nil, fmt.Errorf("missing/duplicate training sample %s", id)
			}
			l, ok := labelFor(s, p.Product)
			if !ok || l.Present != set.want {
				return nil, nil, fmt.Errorf("training label missing or contradictory: %s", id)
			}
			trainIDs[id] = true
			trainGroups[s.Group] = true
			if h := host(s); h != "" {
				trainHosts[h] = true
			}
			trainHashes[s.ContentSHA256] = true
			if p.Probe != "" {
				probe, ok := samples[s.Probes[p.Probe]]
				if !ok || probe.Group != s.Group {
					return nil, nil, fmt.Errorf("missing or different-host probe for %s", id)
				}
				trainHashes[probe.ContentSHA256] = true
			}
		}
	}
	var test []replaySample
	var excluded []string
	seen := map[string]bool{}
	for _, s := range m.Samples {
		if _, ok := labelFor(s, p.Product); !ok || trainIDs[s.ID] {
			continue
		}
		hash := s.ContentSHA256
		if p.Probe != "" {
			probe, ok := samples[s.Probes[p.Probe]]
			if !ok {
				continue
			}
			hash = probe.ContentSHA256
		}
		if trainGroups[s.Group] || trainHosts[host(s)] || trainHashes[hash] || seen[hash] {
			excluded = append(excluded, s.ID)
			continue
		}
		seen[hash] = true
		test = append(test, s)
	}
	return test, excluded, nil
}
func generateReplay(m *replayManifest, j *judge.Judge, out string) ([]generationResult, error) {
	samples := map[string]replaySample{}
	for _, s := range m.Samples {
		samples[s.ID] = s
	}
	results := make([]generationResult, 0, len(m.Generation))
	plans := map[string]bool{}
	for _, p := range m.Generation {
		if plans[p.Name] {
			return nil, fmt.Errorf("duplicate generation plan %s", p.Name)
		}
		plans[p.Name] = true
		r := generationResult{Name: p.Name, Training: map[string]*common.Framework{}, Holdout: map[string]*common.Framework{}}
		test, excluded, err := generationSplit(m, p)
		if err != nil {
			return nil, err
		}
		r.Excluded = excluded
		g := gen.New(j, p.Product)
		for _, id := range p.Positive {
			s := samples[id]
			g.Positive(s.raw)
			if p.Probe != "" {
				g.Probe([]byte(p.Probe), samples[s.Probes[p.Probe]].raw)
			}
		}
		for _, id := range p.Negative {
			s := samples[id]
			g.Negative(s.raw)
			if p.Probe != "" {
				g.Probe([]byte(p.Probe), samples[s.Probes[p.Probe]].raw)
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		f, err := g.Generate(ctx)
		cancel()
		if err != nil {
			r.Error = err.Error()
			results = append(results, r)
			continue
		}
		data, err := yaml.Marshal(f)
		if err != nil {
			return nil, err
		}
		dir := filepath.Join(out, "fingerprints")
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, err
		}
		r.File = filepath.ToSlash(filepath.Join("fingerprints", p.Name+".yaml"))
		if err := os.WriteFile(filepath.Join(out, r.File), data, 0600); err != nil {
			return nil, err
		}
		var loaded fingerlib.Finger
		if err := yaml.Unmarshal(data, &loaded); err != nil {
			return nil, err
		}
		if err := loaded.Compile(false); err != nil {
			return nil, err
		}
		// Revalidate the exported rule on training samples before holding it out.
		if err := g.Validate(&loaded); err != nil {
			r.Error = err.Error()
			results = append(results, r)
			continue
		}
		// Preserve native detections, including nil for a tested non-match.
		// Truth remains in the manifest and never enters generation.
		for _, ids := range [][]string{p.Positive, p.Negative} {
			for _, id := range ids {
				r.Training[id] = evaluateGenerated(&loaded, p, samples[id], samples)
			}
		}
		for _, sample := range test {
			r.Holdout[sample.ID] = evaluateGenerated(&loaded, p, sample, samples)
		}
		results = append(results, r)
	}
	if err := writeJSON(filepath.Join(out, "generation.json"), results); err != nil {
		return nil, err
	}
	return results, nil
}

func evaluateGenerated(f *fingerlib.Finger, p generationPlan, s replaySample, samples map[string]replaySample) *common.Framework {
	var frame *common.Framework
	var matched bool
	if p.Probe == "" {
		frame, _, matched = f.PassiveMatch(fingerlib.NewContent(s.raw, "", true))
	} else {
		frame, _, matched = f.ActiveMatch(2, func(request []byte) ([]byte, bool) {
			id, ok := s.Probes[string(request)]
			return samples[id].raw, ok
		})
	}
	if !matched {
		return nil
	}
	return frame
}
