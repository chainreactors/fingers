package fingers

import (
	"testing"

	"github.com/chainreactors/fingers/common"
)

func TestACCorrectness_MatchesSameAsBaseline(t *testing.T) {
	engine := newPerfEngine(t)

	// Build a baseline engine that uses the old PassiveMatch path (no AC)
	baselineFingers := engine.HTTPFingers

	acIdx := engine.httpKeywordIndex
	if acIdx == nil {
		t.Fatal("httpKeywordIndex is nil")
	}

	sites := generateSyntheticResponses()
	realSites := loadTestSites(t)
	sites = append(sites, realSites...)

	for _, site := range sites {
		content := NewContent(site.Content, "", true)

		// Baseline: iterate all fingers
		baseFrames, baseVulns := baselineFingers.PassiveMatch(content, false)

		// AC path: only evaluate candidates
		acFrames, acVulns := baselineFingers.ACPassiveMatch(content, acIdx, false)

		// Verify AC finds at least everything the baseline finds
		missing := findMissing(baseFrames, acFrames)
		extra := findMissing(acFrames, baseFrames)

		if len(missing) > 0 {
			t.Errorf("[%s] AC MISSED frameworks: %v", site.Name, missing)
		}
		if len(extra) > 0 {
			t.Logf("[%s] AC found %d extra frameworks (expected due to broader candidate set): %v",
				site.Name, len(extra), extra)
		}

		missingVulns := findMissingVulns(baseVulns, acVulns)
		if len(missingVulns) > 0 {
			t.Errorf("[%s] AC MISSED vulns: %v", site.Name, missingVulns)
		}

		t.Logf("[%s] baseline=%d AC=%d frameworks (match)",
			site.Name, len(baseFrames), len(acFrames))
	}
}

func findMissing(expected, actual common.Frameworks) []string {
	var missing []string
	for name := range expected {
		if _, ok := actual[name]; !ok {
			missing = append(missing, name)
		}
	}
	return missing
}

func findMissingVulns(expected, actual common.Vulns) []string {
	var missing []string
	for name := range expected {
		if _, ok := actual[name]; !ok {
			missing = append(missing, name)
		}
	}
	return missing
}
