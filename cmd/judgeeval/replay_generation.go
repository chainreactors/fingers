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

type generationCase struct {
	ID              string  `json:"id"`
	Present         bool    `json:"present"`
	Matched         bool    `json:"matched"`
	Version         string  `json:"version,omitempty"`
	ExpectedVersion *string `json:"expected_version,omitempty"`
}
type generationResult struct {
	Name              string           `json:"name"`
	Product           string           `json:"product"`
	Status            string           `json:"status"`
	File              string           `json:"file,omitempty"`
	Detection         detectionScore   `json:"detection"`
	Versions          versionScore     `json:"versions"`
	TrainingDetection detectionScore   `json:"training_detection"`
	TrainingVersions  versionScore     `json:"training_versions"`
	TrainingCases     []generationCase `json:"training_cases"`
	Cases             []generationCase `json:"cases"`
	Excluded          []string         `json:"excluded"`
	Error             string           `json:"error,omitempty"`
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
		r := generationResult{Name: p.Name, Product: p.Product, Status: "failed"}
		test, excluded, err := generationSplit(m, p)
		if err != nil {
			return nil, err
		}
		r.Excluded = excluded
		g := gen.New(j)
		if !p.AutoName {
			g.Name(p.Product)
		}
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
		r.Product = f.Name
		if judge.NormalizeName(f.Name) != judge.NormalizeName(p.Product) {
			r.Error = "automatic name differs from labelled product"
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
		// Score inferred training versions only after generation and export.
		// Positive deliberately receives no labelled version or other truth.
		for _, ids := range [][]string{p.Positive, p.Negative} {
			for _, id := range ids {
				c, frame := evaluateGenerated(&loaded, p, samples[id], samples)
				r.TrainingCases = append(r.TrainingCases, c)
				r.TrainingDetection.add(c.Present, c.Matched)
				if c.ExpectedVersion != nil {
					r.TrainingVersions.add(frame, *c.ExpectedVersion)
				}
			}
		}
		for _, s := range test {
			c, frame := evaluateGenerated(&loaded, p, s, samples)
			r.Cases = append(r.Cases, c)
			r.Detection.add(c.Present, c.Matched)
			if c.ExpectedVersion != nil {
				r.Versions.add(frame, *c.ExpectedVersion)
			}
		}
		switch {
		case r.TrainingDetection.FP > 0 || r.TrainingDetection.FN > 0 || r.TrainingVersions.Wrong > 0 || r.TrainingVersions.Missing > 0 || r.TrainingVersions.Unsupported > 0:
			r.Status = "failed_training"
		case r.Detection.FP > 0 || r.Detection.FN > 0 || r.Versions.Wrong > 0 || r.Versions.Missing > 0 || r.Versions.Unsupported > 0:
			r.Status = "failed_holdout"
		case r.Detection.TP == 0 || r.Detection.TN == 0:
			r.Status = "insufficient_holdout"
		default:
			r.Status = "passed_holdout"
		}
		results = append(results, r)
	}
	if err := writeJSON(filepath.Join(out, "generation.json"), results); err != nil {
		return nil, err
	}
	return results, nil
}

func evaluateGenerated(f *fingerlib.Finger, p generationPlan, s replaySample, samples map[string]replaySample) (generationCase, *common.Framework) {
	l, _ := labelFor(s, p.Product)
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
	c := generationCase{ID: s.ID, Present: l.Present, Matched: matched, ExpectedVersion: l.Version}
	if matched && frame != nil {
		c.Version = frame.Version
	}
	return c, frame
}
