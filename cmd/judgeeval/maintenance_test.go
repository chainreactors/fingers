package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/chainreactors/fingers"
)

func TestMaintenanceCountsHostAndOperatorOverlapOnce(t *testing.T) {
	samples := []replaySample{
		{URL: "https://a.example/one", Group: "operator-a"},
		{URL: "https://b.example/", Group: "operator-a"},
		{URL: "https://b.example/two", Group: "operator-b"},
		{URL: "https://c.example/", Group: "operator-b"},
		{URL: "https://d.example/", Group: "operator-d"},
	}
	if got := independentHostCount(samples); got != 2 {
		t.Fatalf("overlapping hosts/operators counted %d times, want 2", got)
	}
}

func TestMaintenanceRecognizesPreviouslyLoadedLibrary(t *testing.T) {
	engine, err := fingers.NewEngine(fingers.FingersEngine)
	if err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	path := filepath.Join(out, "fixture.yaml")
	data := []byte("- name: replay-maintenance-test-app\n  protocol: http\n  rule:\n    - regexps:\n        body:\n          - '<title>replay-maintenance-test-app</title>'\n")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := loadReplayLibrary(engine, path, out); err != nil {
		t.Fatal(err)
	}
	archived, err := os.ReadFile(filepath.Join(out, "input-library.yaml"))
	if err != nil || string(archived) != string(data) {
		t.Fatalf("library bytes not preserved: %v", err)
	}
	catalog, err := runtimeCatalog(engine)
	if err != nil {
		t.Fatal(err)
	}
	existing := catalogMatches([]catalogSource{catalog}, []string{"replay-maintenance-test-app"})
	if got := maintenanceDecision(existing, generationResult{Status: "passed_holdout"}, 2, 5); got != "already_catalogued" {
		t.Fatalf("would re-add existing library fingerprint: %s", got)
	}
}

func TestCatalogAuditCoversEveryEmbeddedSource(t *testing.T) {
	catalog, err := embeddedCatalog()
	if err != nil {
		t.Fatal(err)
	}
	if len(catalog) != 6 {
		t.Fatalf("sources: %d", len(catalog))
	}
	for _, source := range catalog {
		if source.SHA256 == "" || len(source.Names) == 0 {
			t.Fatalf("incomplete source: %s", source.Source)
		}
	}
	if len(catalogMatches(catalog, []string{"WordPress"})) == 0 {
		t.Fatal("known product missed")
	}
	if len(catalogMatches(catalog, []string{"certainly-not-a-real-catalog-product-20260926"})) != 0 {
		t.Fatal("invented product matched")
	}
}

func TestMaintenanceRequiresNoveltyAndIndependentHosts(t *testing.T) {
	g := generationResult{Status: "passed_holdout"}
	for _, tc := range []struct {
		existing           []string
		positive, negative int
		want               string
	}{
		{[]string{"fingers:nginx"}, 3, 20, "already_catalogued"},
		{nil, 1, 20, "insufficient_independent_hosts"},
		{nil, 2, 4, "insufficient_independent_hosts"},
		{nil, 2, 5, "eligible"},
	} {
		if got := maintenanceDecision(tc.existing, g, tc.positive, tc.negative); got != tc.want {
			t.Fatalf("got %s want %s", got, tc.want)
		}
	}
	g.Status = "failed_holdout"
	if got := maintenanceDecision(nil, g, 3, 20); got != "failed_holdout" {
		t.Fatalf("failed candidate admitted: %s", got)
	}
}
