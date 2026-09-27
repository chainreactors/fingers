package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chainreactors/fingers/common"
	"github.com/chainreactors/fingers/judge"
)

func TestGenerationRecordsNativeObservations(t *testing.T) {
	plan := generationPlan{Name: "jenkins", Product: "Jenkins", Positive: []string{"train-positive"}, Negative: []string{"train-negative"}}
	m := &replayManifest{Generation: []generationPlan{plan}}
	for _, item := range []struct{ id, version string }{
		{"train-positive", "2.401.3"}, {"train-negative", ""}, {"test-positive", "2.402.1"}, {"test-negative", ""},
	} {
		raw := "HTTP/1.1 200 OK\r\n"
		if item.version != "" {
			raw += "X-Jenkins: " + item.version + "\r\n"
		}
		raw += "\r\n<title>" + item.id + "</title>"
		label := productLabel{Product: "Jenkins", Present: item.version != ""}
		if label.Present {
			label.Version = stringPtr(item.version)
		}
		m.Samples = append(m.Samples, replaySample{ID: item.id, Group: item.id, ContentSHA256: digest([]byte(raw)), raw: []byte(raw), Labels: []productLabel{label}})
	}
	out := t.TempDir()
	// Explicit response headers establish versions without any model calls.
	results, err := generateReplay(m, judge.New(nil), out)
	if err != nil || len(results) != 1 {
		t.Fatalf("generation=%v error=%v", results, err)
	}
	data, err := os.ReadFile(filepath.Join(out, "generation.json"))
	if err != nil {
		t.Fatal(err)
	}
	var restored []generationResult
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatal(err)
	}
	r := restored[0]
	training, holdout, status := r.assess(m, plan)
	if status != "passed_holdout" || training.Detection.TP != 1 || training.Detection.TN != 1 || training.Versions.Correct != 1 || holdout.Versions.Correct != 1 || holdout.Detection.TN != 1 {
		t.Fatalf("status=%s training=%+v holdout=%+v error=%s", status, training, holdout, r.Error)
	}
	if frame, tested := r.Holdout["test-negative"]; !tested || frame != nil {
		t.Fatal("evaluated non-match was lost")
	}
	if frame := r.Holdout["test-positive"]; frame == nil || frame.Name != "Jenkins" || versionOf(frame) != "2.402.1" {
		t.Fatalf("native framework lost: %+v", frame)
	}
	if _, err := os.Stat(filepath.Join(out, r.File)); err != nil {
		t.Fatal(err)
	}
	var fields []map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"product", "status", "detection", "versions", "training_detection", "training_versions", "training_cases", "cases"} {
		if _, exists := fields[0][name]; exists {
			t.Fatalf("redundant generation field %s", name)
		}
	}
	// Scores and conclusions follow the current labels and observations.
	m.Samples[2].Labels[0].Version = stringPtr("9.9.9")
	_, holdout, status = r.assess(m, plan)
	if status != "failed_holdout" || holdout.Versions.Wrong != 1 {
		t.Fatalf("stale assessment after label change: %s %+v", status, holdout)
	}
	r.Holdout["test-positive"].Version = "9.9.9"
	_, _, status = r.assess(m, plan)
	if status != "passed_holdout" {
		t.Fatalf("stale assessment after observation change: %s", status)
	}
	report := filepath.Join(out, "report.md")
	if err := writeReplayReport(report, summarizeReplay(m, nil, []generationResult{r}, nil), m); err != nil {
		t.Fatal(err)
	}
	text, err := os.ReadFile(report)
	if err != nil || !strings.Contains(string(text), "passed_holdout") {
		t.Fatalf("report assessment missing: %s, %v", text, err)
	}
}

func TestGenerationAssessmentRequiresEveryExpectedObservation(t *testing.T) {
	plan := generationPlan{Name: "product", Product: "Product", Positive: []string{"train-positive"}, Negative: []string{"train-negative"}}
	m := &replayManifest{}
	for _, id := range []string{"train-positive", "train-negative", "test-positive", "test-negative", "second-negative"} {
		m.Samples = append(m.Samples, replaySample{ID: id, Group: id, ContentSHA256: id, Labels: []productLabel{{Product: plan.Product, Present: strings.HasSuffix(id, "positive")}}})
	}
	for _, change := range []string{"none", "missing training", "wrong training key", "missing holdout", "wrong holdout key", "false negative", "error"} {
		t.Run(change, func(t *testing.T) {
			frame := common.NewFramework(plan.Product, common.FrameFromFingers)
			r := generationResult{Training: map[string]*common.Framework{"train-positive": frame, "train-negative": nil}, Holdout: map[string]*common.Framework{"test-positive": frame, "test-negative": nil, "second-negative": nil}}
			want := "passed_holdout"
			switch change {
			case "missing training", "wrong training key":
				delete(r.Training, "train-negative")
				if change == "wrong training key" {
					r.Training["test-negative"] = nil
				}
				want = "failed_training"
			case "missing holdout", "wrong holdout key":
				delete(r.Holdout, "second-negative")
				if change == "wrong holdout key" {
					r.Holdout["train-negative"] = nil
				}
				want = "insufficient_holdout"
			case "false negative":
				r.Holdout["test-positive"] = nil
				want = "failed_holdout"
			case "error":
				r.Error = "generation failed"
				want = "failed"
			}
			_, _, status := r.assess(m, plan)
			if status != want {
				t.Fatalf("status=%s want=%s", status, want)
			}
		})
	}
}
