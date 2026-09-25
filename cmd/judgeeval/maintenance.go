package main

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/chainreactors/fingers"
	"github.com/chainreactors/fingers/common"
	fingerlib "github.com/chainreactors/fingers/fingers"
	"github.com/chainreactors/fingers/judge"
	"github.com/chainreactors/fingers/resources"
	"gopkg.in/yaml.v3"
)

// CLI evidence records; generated SDK values remain native Finger/Frameworks.
func loadReplayLibrary(engine *fingers.Engine, path, out string) error {
	// Read a local file and archive the exact bytes before using the public loader.
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	snapshot := filepath.Join(out, "input-library.yaml")
	if err := os.WriteFile(snapshot, data, 0600); err != nil {
		return err
	}
	if err := engine.Fingers().LoadFromYAML(snapshot); err != nil {
		return err
	}
	return engine.Compile()
}

type catalogSource struct {
	Source string   `json:"source"`
	SHA256 string   `json:"sha256"`
	Names  []string `json:"names"`
}

func embeddedCatalog() ([]catalogSource, error) {
	var result []catalogSource
	for _, source := range []struct {
		name string
		data []byte
	}{
		{"fingers", resources.FingersHTTPData}, {"goby", resources.GobyData},
		{"ehole", resources.EholeData}, {"wappalyzer", resources.WappalyzerData},
		{"fingerprinthub", resources.FingerprinthubWebData},
	} {
		var raw interface{}
		if err := resources.UnmarshalData(source.data, &raw); err != nil {
			return nil, err
		}
		var entries []interface{}
		var names []string
		switch source.name {
		case "wappalyzer":
			root, ok := raw.(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("invalid %s catalog", source.name)
			}
			apps, ok := root["apps"].(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("invalid apps catalog")
			}
			for name := range apps {
				names = append(names, name)
			}
		case "ehole":
			root, ok := raw.(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("invalid ehole catalog")
			}
			entries, _ = root["fingerprint"].([]interface{})
		default:
			entries, _ = raw.([]interface{})
		}
		for _, entry := range entries {
			obj, ok := entry.(map[string]interface{})
			if !ok {
				continue
			}
			for _, key := range []string{"name", "cms", "id"} {
				if name, ok := obj[key].(string); ok {
					names = append(names, name)
				}
			}
			if info, ok := obj["info"].(map[string]interface{}); ok {
				if name, ok := info["name"].(string); ok {
					names = append(names, name)
				}
				if metadata, ok := info["metadata"].(map[string]interface{}); ok {
					if name, ok := metadata["product"].(string); ok {
						names = append(names, name)
					}
				}
			}
		}
		if len(names) == 0 {
			return nil, fmt.Errorf("empty %s catalog", source.name)
		}
		result = append(result, catalogSource{source.name, digest(source.data), uniqueNames(names)})
	}
	var aliases []struct {
		Name  string              `yaml:"name"`
		Alias map[string][]string `yaml:"alias"`
	}
	if err := yaml.Unmarshal(resources.AliasesData, &aliases); err != nil {
		return nil, err
	}
	var names []string
	for _, alias := range aliases {
		names = append(names, alias.Name)
		for _, values := range alias.Alias {
			names = append(names, values...)
		}
	}
	result = append(result, catalogSource{"aliases", digest(resources.AliasesData), uniqueNames(names)})
	return result, nil
}

func runtimeCatalog(engine *fingers.Engine) (catalogSource, error) {
	data, err := yaml.Marshal(engine.Fingers().HTTPFingers)
	if err != nil {
		return catalogSource{}, err
	}
	var names []string
	for _, f := range engine.Fingers().HTTPFingers {
		if f != nil {
			names = append(names, f.Name)
		}
	}
	return catalogSource{"runtime-fingers", digest(data), uniqueNames(names)}, nil
}

// Shared operator groups or shared hostnames connect samples into one unit.
// Different user-supplied group labels cannot turn one host into multiple votes.
func independentHostCount(samples []replaySample) int {
	parent := map[string]string{}
	var root func(string) string
	root = func(key string) string {
		if _, ok := parent[key]; !ok {
			parent[key] = key
		}
		if parent[key] != key {
			parent[key] = root(parent[key])
		}
		return parent[key]
	}
	var hosts []string
	for _, s := range samples {
		u, err := url.Parse(s.URL)
		if err != nil || u.Hostname() == "" || s.Group == "" {
			continue
		}
		host := "host:" + strings.ToLower(u.Hostname())
		group := "group:" + s.Group
		parent[root(host)] = root(group)
		hosts = append(hosts, host)
	}
	groups := map[string]bool{}
	for _, host := range hosts {
		groups[root(host)] = true
	}
	return len(groups)
}

func uniqueNames(names []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, name := range names {
		if name != "" && !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

func catalogMatches(catalog []catalogSource, names []string) []string {
	wanted := map[string]bool{}
	for _, name := range names {
		wanted[judge.NormalizeName(name)] = true
	}
	var found []string
	for _, source := range catalog {
		for _, name := range source.Names {
			if wanted[judge.NormalizeName(name)] {
				found = append(found, source.Source+":"+name)
			}
		}
	}
	return uniqueNames(found)
}

type maintenanceProduct struct {
	Plan               string     `json:"plan"`
	Product            string     `json:"product"`
	Status             string     `json:"status"`
	Existing           []string   `json:"existing_catalog_matches"`
	PositiveSamples    int        `json:"positive_samples"`
	SuggestedPositives int        `json:"suggested_positives"`
	UnknownPositives   int        `json:"unknown_positives"`
	PositiveHosts      int        `json:"holdout_positive_hosts"`
	NegativeHosts      int        `json:"holdout_negative_hosts"`
	Before             stageScore `json:"before"`
	After              stageScore `json:"after"`
	TestIDs            []string   `json:"test_ids"`
}

type maintenanceReport struct {
	Library           string               `json:"library,omitempty"`
	CatalogFile       string               `json:"catalog_file"`
	MinPositiveHosts  int                  `json:"min_positive_hosts"`
	MinNegativeHosts  int                  `json:"min_negative_hosts"`
	Products          []maintenanceProduct `json:"products"`
	LostExisting      []string             `json:"lost_existing_hits"`
	ChangedVersions   []string             `json:"changed_existing_versions"`
	IntegrationErrors []string             `json:"integration_errors"`
}

func maintenanceDecision(existing []string, g generationResult, positiveHosts, negativeHosts int) string {
	switch {
	case len(existing) > 0:
		return "already_catalogued"
	case g.Status != "passed_holdout":
		return g.Status
	case positiveHosts < 2 || negativeHosts < 5:
		return "insufficient_independent_hosts"
	default:
		return "eligible"
	}
}

func maintainReplay(m *replayManifest, rows []replayRow, generated []generationResult, out string, engine *fingers.Engine) error {
	catalog, err := embeddedCatalog()
	if err != nil {
		return err
	}
	runtime, err := runtimeCatalog(engine)
	if err != nil {
		return err
	}
	catalog = append(catalog, runtime)
	if err := writeJSON(filepath.Join(out, "catalog-before.json"), catalog); err != nil {
		return err
	}
	report := maintenanceReport{CatalogFile: "catalog-before.json", MinPositiveHosts: 2, MinNegativeHosts: 5}
	byID := map[string]replayRow{}
	for _, row := range rows {
		byID[row.ID] = row
	}
	plans := map[string]generationPlan{}
	for _, p := range m.Generation {
		plans[p.Name] = p
	}
	var library fingerlib.Fingers
	accepted := map[string]generationPlan{}
	for _, g := range generated {
		p := plans[g.Name]
		r := maintenanceProduct{Plan: g.Name, Product: p.Product}
		names := []string{p.Product, g.Product}
		for _, sample := range m.Samples {
			l, ok := labelFor(sample, p.Product)
			if !ok {
				continue
			}
			names = append(names, l.Aliases...)
			if l.Present {
				r.PositiveSamples++
				row := byID[sample.ID]
				if containsProductName(row.Suggestions, l) {
					r.SuggestedPositives++
				}
				if row.Unknown {
					r.UnknownPositives++
				}
			}
		}
		r.Existing = catalogMatches(catalog, names)
		test, _, err := generationSplit(m, p)
		if err != nil {
			return err
		}
		var pos, neg []replaySample
		for _, sample := range test {
			l, _ := labelFor(sample, p.Product)
			if l.Present {
				pos = append(pos, sample)
			} else {
				neg = append(neg, sample)
			}
			r.TestIDs = append(r.TestIDs, sample.ID)
		}
		r.PositiveHosts, r.NegativeHosts = independentHostCount(pos), independentHostCount(neg)
		r.Status = maintenanceDecision(r.Existing, g, r.PositiveHosts, r.NegativeHosts)
		if r.Status == "eligible" && p.Probe != "" {
			r.Status = "active_integration_not_evaluated"
		}
		if r.Status == "eligible" {
			key := judge.NormalizeName(p.Product)
			if _, exists := accepted[key]; exists {
				r.Status = "duplicate_candidate"
			} else {
				path, err := confinedPath(out, g.File)
				if err != nil {
					return err
				}
				data, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				var f fingerlib.Finger
				if err := yaml.Unmarshal(data, &f); err != nil {
					return err
				}
				library = append(library, &f)
				accepted[key] = p
			}
		}
		report.Products = append(report.Products, r)
	}
	if len(library) == 0 {
		return writeJSON(filepath.Join(out, "maintenance.json"), report)
	}
	sort.Slice(library, func(i, j int) bool { return library[i].Name < library[j].Name })
	data, err := yaml.Marshal(library)
	if err != nil {
		return err
	}
	candidatePath := filepath.Join(out, "library.candidate.yaml")
	if err := os.WriteFile(candidatePath, data, 0600); err != nil {
		return err
	}
	before := map[string]common.Frameworks{}
	for _, sample := range m.Samples {
		frames, err := engine.DetectContent(sample.raw)
		if err != nil {
			return err
		}
		before[sample.ID] = copyFrames(frames)
	}
	// Exercise the public additive loader and rebuild aliases just as SDK callers do.
	if err := engine.Fingers().LoadFromYAML(candidatePath); err != nil {
		return err
	}
	if err := engine.Compile(); err != nil {
		return err
	}
	after := map[string]common.Frameworks{}
	for _, sample := range m.Samples {
		frames, err := engine.DetectContent(sample.raw)
		if err != nil {
			return err
		}
		after[sample.ID] = frames
		for _, f := range before[sample.ID] {
			if f == nil {
				continue
			}
			got := findLabel(frames, productLabel{Product: f.Name})
			if got == nil {
				report.LostExisting = append(report.LostExisting, sample.ID+":"+f.Name)
			} else if f.Version != "" && got.Version != f.Version {
				report.ChangedVersions = append(report.ChangedVersions, sample.ID+":"+f.Name)
			}
		}
		for _, p := range accepted {
			l, ok := labelFor(sample, p.Product)
			if !ok {
				continue
			}
			got := findLabel(frames, l)
			if (got != nil) != l.Present || got != nil && l.Version != nil && got.Version != *l.Version {
				report.IntegrationErrors = append(report.IntegrationErrors, sample.ID+":"+p.Product)
			}
		}
	}
	for i := range report.Products {
		r := &report.Products[i]
		if r.Status != "eligible" {
			continue
		}
		p := plans[r.Plan]
		test, _, _ := generationSplit(m, p)
		for _, sample := range test {
			l, _ := labelFor(sample, p.Product)
			for _, stage := range []struct {
				score  *stageScore
				frames common.Frameworks
			}{{&r.Before, before[sample.ID]}, {&r.After, after[sample.ID]}} {
				f := findLabel(stage.frames, l)
				stage.score.Detection.add(l.Present, f != nil)
				if l.Version != nil {
					stage.score.Versions.add(f, *l.Version)
				}
			}
		}
		r.Status = "validated_library"
	}
	sort.Strings(report.LostExisting)
	sort.Strings(report.ChangedVersions)
	sort.Strings(report.IntegrationErrors)
	if len(report.LostExisting)+len(report.ChangedVersions)+len(report.IntegrationErrors) > 0 {
		for i := range report.Products {
			if report.Products[i].Status == "validated_library" {
				report.Products[i].Status = "integration_failed"
			}
		}
	} else {
		report.Library = "library.yaml"
		if err := os.Rename(candidatePath, filepath.Join(out, report.Library)); err != nil {
			return err
		}
	}
	if err := writeJSON(filepath.Join(out, "maintenance.json"), report); err != nil {
		return err
	}
	if report.Library == "" {
		return fmt.Errorf("candidate library failed integration; see maintenance.json")
	}
	fmt.Fprintf(os.Stderr, "validated %d novel fingerprints in %s\n", len(library), report.Library)
	return nil
}
