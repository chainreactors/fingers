package judge

import (
	"bytes"
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/chainreactors/fingers/common"
	fingerlib "github.com/chainreactors/fingers/fingers"
)

// Generator builds one native Finger from labelled HTTP responses. Probe
// belongs to the most recently added positive or negative sample.
type Generator struct {
	judge    *Judge
	name     string
	positive []generatorSample
	negative []generatorSample
	current  *generatorSample
	err      error
}

type generatorSample struct {
	raw     []byte
	version string
	probes  map[string][]byte
}

// NewGenerator creates a fingerprint generator using j for name and version
// selection. A Name hint lets rule generation work without a provider.
func NewGenerator(j *Judge) *Generator { return &Generator{judge: j} }

// Name supplies a known product name. Without it Generate selects a name
// from the positive responses.
func (g *Generator) Name(name string) *Generator {
	g.name = strings.TrimSpace(name)
	return g
}

// Positive adds an HTTP response known to belong to the product.
func (g *Generator) Positive(raw []byte) *Generator {
	g.positive = append(g.positive, generatorSample{raw: bytes.Clone(raw), probes: map[string][]byte{}})
	g.current = &g.positive[len(g.positive)-1]
	return g
}

// PositiveVersion adds a positive response with an authoritative version.
func (g *Generator) PositiveVersion(raw []byte, version string) *Generator {
	g.Positive(raw)
	g.positive[len(g.positive)-1].version = strings.TrimSpace(version)
	return g
}

// Negative adds an HTTP response known not to belong to the product.
func (g *Generator) Negative(raw []byte) *Generator {
	g.negative = append(g.negative, generatorSample{raw: bytes.Clone(raw), probes: map[string][]byte{}})
	g.current = &g.negative[len(g.negative)-1]
	return g
}

// Probe attaches a recorded request and response to the last sample. request
// is the exact send_data used by the rule engine.
func (g *Generator) Probe(request, response []byte) *Generator {
	if g.current == nil {
		g.err = fmt.Errorf("judge: Probe requires a preceding Positive or Negative")
		return g
	}
	if len(request) == 0 {
		g.err = fmt.Errorf("judge: Probe requires non-empty send_data")
		return g
	}
	g.current.probes[string(request)] = bytes.Clone(response)
	return g
}

// ProbeWith sends request and records the response for the last sample. The
// caller controls network behavior through send.
func (g *Generator) ProbeWith(ctx context.Context, request []byte, send func(context.Context, []byte) ([]byte, error)) error {
	if g.current == nil {
		return fmt.Errorf("judge: ProbeWith requires a preceding Positive or Negative")
	}
	if send == nil || len(request) == 0 {
		return fmt.Errorf("judge: ProbeWith requires a sender and non-empty send_data")
	}
	response, err := send(ctx, request)
	if err != nil {
		return err
	}
	g.Probe(request, response)
	return nil
}

// Generate returns one compiled, rule-validated fingerprint. It never writes
// a templates repository. At least one positive and one negative are required.
func (g *Generator) Generate(ctx context.Context) (*fingerlib.Finger, error) {
	if g.err != nil {
		return nil, g.err
	}
	if len(g.positive) == 0 || len(g.negative) == 0 {
		return nil, fmt.Errorf("judge: Generate requires positive and negative samples")
	}
	if err := g.validateSamples(); err != nil {
		return nil, err
	}
	name := g.name
	if name == "" {
		if g.judge == nil {
			return nil, fmt.Errorf("judge: a Judge or Name is required to select a product name")
		}
		counts := map[string]int{}
		ranks := map[string]int{}
		labels := map[string]string{}
		for _, sample := range g.positive {
			names, err := g.judge.SuggestNames(ctx, sample.raw)
			if err != nil {
				return nil, err
			}
			for rank, candidate := range names {
				key := NormalizeName(candidate)
				counts[key]++
				ranks[key] += len(names) - rank
				if labels[key] == "" {
					labels[key] = candidate
				}
			}
		}
		var keys []string
		for key := range counts {
			keys = append(keys, key)
		}
		sort.Slice(keys, func(a, b int) bool {
			if counts[keys[a]] != counts[keys[b]] {
				return counts[keys[a]] > counts[keys[b]]
			}
			if ranks[keys[a]] != ranks[keys[b]] {
				return ranks[keys[a]] > ranks[keys[b]]
			}
			return keys[a] < keys[b]
		})
		if len(keys) == 0 || counts[keys[0]] != len(g.positive) {
			return nil, fmt.Errorf("judge: no product name supported by every positive sample; provide Name")
		}
		name = labels[keys[0]]
	}

	versions := make([]string, len(g.positive))
	for i, sample := range g.positive {
		versions[i] = sample.version
		if versions[i] == "" && g.judge != nil {
			v, err := g.judge.Version(ctx, sample.raw, common.NewFramework(name, common.FrameFromGUESS))
			if err != nil {
				return nil, err
			}
			versions[i] = v
		}
	}

	f := &fingerlib.Finger{Name: name, Protocol: fingerlib.HTTPProtocol}
	f.Rules = append(f.Rules, g.rules("", name)...)
	hasVersion := false
	for _, version := range versions {
		hasVersion = hasVersion || version != ""
	}
	for _, request := range g.probeRequests() {
		if hasVersion {
			if rule := g.versionRule(request, name, versions); rule != nil {
				f.Rules = append(f.Rules, rule)
				f.Rules = append(f.Rules, g.rules(request, name)...)
			}
		} else {
			f.Rules = append(f.Rules, g.rules(request, name)...)
		}
	}
	if len(f.Rules) == 0 {
		return nil, fmt.Errorf("judge: no rule distinguishes the positive and negative samples")
	}
	if rule := g.versionRule("", name, versions); rule != nil {
		f.Rules = append(fingerlib.Rules{rule}, f.Rules...)
	}
	if err := g.Validate(f); err != nil {
		return nil, err
	}
	if err := f.Compile(false); err != nil {
		return nil, err
	}
	return f, nil
}

// Validate checks the generated or edited Finger against every recorded
// positive and negative using the rule engine, without calling the provider.
func (g *Generator) Validate(f *fingerlib.Finger) error {
	if g.err != nil {
		return g.err
	}
	if f == nil || len(f.Rules) == 0 {
		return fmt.Errorf("judge: fingerprint has no rules")
	}
	if len(g.positive) == 0 || len(g.negative) == 0 {
		return fmt.Errorf("judge: validation requires positive and negative samples")
	}
	if err := g.validateSamples(); err != nil {
		return err
	}
	for i, rule := range f.Rules {
		if rule == nil {
			return fmt.Errorf("judge: rule %d is nil", i)
		}
	}
	checking := copyFingerForValidation(f)
	if err := checking.Compile(false); err != nil {
		return err
	}
	check := func(sample generatorSample) (*common.Framework, bool) {
		sender := func(request []byte) ([]byte, bool) {
			response, ok := sample.probes[string(request)]
			return response, ok
		}
		frame, _, ok := checking.Match(fingerlib.NewContent(sample.raw, "", true), 2, sender)
		return frame, ok
	}
	for i, sample := range g.positive {
		frame, ok := check(sample)
		if !ok {
			return fmt.Errorf("judge: positive sample %d did not match", i)
		}
		if sample.version != "" && frame.Version != sample.version {
			return fmt.Errorf("judge: positive sample %d version = %q, want %q", i, frame.Version, sample.version)
		}
	}
	for i, sample := range g.negative {
		if _, ok := check(sample); ok {
			return fmt.Errorf("judge: negative sample %d matched", i)
		}
	}
	return nil
}

func (g *Generator) validateSamples() error {
	for _, sample := range append(append([]generatorSample(nil), g.positive...), g.negative...) {
		if _, err := NewPage(sample.raw); err != nil {
			return fmt.Errorf("judge: invalid sample: %w", err)
		}
		for request, response := range sample.probes {
			if request == "" {
				return fmt.Errorf("judge: probe has empty send_data")
			}
			if _, err := NewPage(response); err != nil {
				return fmt.Errorf("judge: invalid probe response: %w", err)
			}
		}
	}
	return nil
}

func copyFingerForValidation(f *fingerlib.Finger) *fingerlib.Finger {
	copy := *f
	copy.Rules = make(fingerlib.Rules, len(f.Rules))
	for i, rule := range f.Rules {
		if rule == nil {
			continue
		}
		cloned := *rule
		if rule.Regexps != nil {
			regexps := *rule.Regexps
			regexps.Body = append([]string(nil), rule.Regexps.Body...)
			regexps.Header = append([]string(nil), rule.Regexps.Header...)
			regexps.CompliedRegexp = nil
			regexps.CompiledVulnRegexp = nil
			regexps.CompiledVersionRegexp = nil
			cloned.Regexps = &regexps
		}
		copy.Rules[i] = &cloned
	}
	return &copy
}

type ruleCandidate struct {
	kind   string
	value  string
	weight int
}

func candidates(raw []byte) []ruleCandidate {
	p, err := NewPage(raw)
	if err != nil {
		return nil
	}
	var out []ruleCandidate
	add := func(kind, value string, weight int) {
		value = strings.ToLower(strings.TrimSpace(value))
		if len(value) >= 5 && len(value) <= 120 {
			out = append(out, ruleCandidate{kind, value, weight})
		}
	}
	for k, v := range p.Headers {
		if k == "Server" || strings.HasPrefix(k, "X-") || k == "Product" {
			value := strings.TrimSpace(nameVersion.ReplaceAllString(strings.Split(v, "/")[0], ""))
			if strings.HasPrefix(k, "X-") && (strings.HasSuffix(k, "-Version") || value == "" || value[0] >= '0' && value[0] <= '9') {
				add("header", k+":", 6)
			} else {
				add("header", k+": "+value, 7)
			}
		}
	}
	add("body", p.Generator, 6)
	// Preserve the declaration, but not a single release or customized title.
	if name := nameVersion.ReplaceAllString(p.Generator, ""); name != "" {
		if loc := reGenerator.FindSubmatchIndex(raw); loc != nil {
			start := loc[2]
			if start < 0 {
				start = loc[4]
			}
			end := start + len(name)
			if end < len(raw) && (raw[end] == '/' || raw[end] == ' ') {
				end++
			}
			add("body", string(raw[loc[0]:end]), 8)
		}
	}
	if !genericName(NormalizeName(p.Title)) {
		if title := reTitle.Find(raw); len(title) > 0 {
			add("body", string(title), 5)
		}
		add("body", p.Title, 4)
	}
	for _, asset := range append(append([]string(nil), p.Scripts...), p.Styles...) {
		path := strings.Split(asset, "?")[0]
		add("body", path, 3)
	}
	for _, comment := range p.Comments {
		add("body", comment, 2)
	}
	for _, name := range pageNames(p) {
		if strings.Contains(strings.ToLower(p.Text), strings.ToLower(name)) {
			add("body", name, 1)
		}
	}
	sort.SliceStable(out, func(a, b int) bool {
		if out[a].weight != out[b].weight {
			return out[a].weight > out[b].weight
		}
		return len(out[a].value) > len(out[b].value)
	})
	return out
}

func containsCandidate(raw []byte, c ruleCandidate) bool {
	content := fingerlib.NewContent(raw, "", true)
	var target []byte
	if c.kind == "header" {
		target = content.Header
	} else {
		target = content.Body
	}
	return bytes.Contains(target, []byte(c.value))
}

func candidateRule(c ruleCandidate) *fingerlib.Rule {
	r := &fingerlib.Rule{Regexps: &fingerlib.Regexps{}}
	if c.kind == "header" {
		r.Regexps.Header = []string{c.value}
	} else {
		r.Regexps.Body = []string{c.value}
	}
	return r
}

func (g *Generator) rules(request, name string) fingerlib.Rules {
	positive, negative, _ := g.responses(request)
	if len(positive) == 0 || len(negative) == 0 {
		return nil
	}
	var rules fingerlib.Rules
	for _, c := range selectCandidates(positive, negative, name) {
		rule := candidateRule(c)
		if request != "" {
			rule.SendDataStr, rule.Level = request, 2
		}
		rules = append(rules, rule)
	}
	return rules
}

// Pick evidence that covers the most still-uncovered positives while staying
// absent from every negative. A single common matcher wins when one exists.
func selectCandidates(positive, negative [][]byte, product ...string) []ruleCandidate {
	if len(positive) == 0 {
		return nil
	}
	options := map[string]ruleCandidate{}
	for _, raw := range positive {
		for _, c := range candidates(raw) {
			// A product must not inherit its proxy/CDN or an unrelated security
			// header merely because that header is absent from a small negative set.
			if c.kind == "header" && len(product) > 0 && !strings.Contains(NormalizeName(c.value), NormalizeName(product[0])) {
				continue
			}
			key := c.kind + "\x00" + c.value
			if previous, ok := options[key]; !ok || c.weight > previous.weight {
				options[key] = c
			}
		}
	}
	covered := make([]bool, len(positive))
	var selected []ruleCandidate
	for len(selected) < len(positive) {
		best, bestCount := ruleCandidate{}, 0
		for _, c := range options {
			valid := true
			for _, raw := range negative {
				if containsCandidate(raw, c) {
					valid = false
					break
				}
			}
			if !valid {
				continue
			}
			count := 0
			for i, raw := range positive {
				if !covered[i] && containsCandidate(raw, c) {
					count++
				}
			}
			if count > bestCount || count == bestCount && count > 0 && (c.weight > best.weight || c.weight == best.weight && (c.value < best.value || c.value == best.value && c.kind < best.kind)) {
				best, bestCount = c, count
			}
		}
		if bestCount == 0 {
			break
		}
		selected = append(selected, best)
		delete(options, best.kind+"\x00"+best.value)
		for i, raw := range positive {
			covered[i] = covered[i] || containsCandidate(raw, best)
		}
		all := true
		for _, ok := range covered {
			all = all && ok
		}
		if all {
			break
		}
	}
	return selected
}

func (g *Generator) probeRequests() []string {
	seen := map[string]bool{}
	var out []string
	for _, sample := range g.positive {
		for request := range sample.probes {
			if !seen[request] {
				seen[request] = true
				out = append(out, request)
			}
		}
	}
	sort.Strings(out)
	return out
}

func (g *Generator) versionRule(request, name string, versions []string) *fingerlib.Rule {
	positive, negative, indices := g.responses(request)
	if len(positive) == 0 || len(negative) == 0 {
		return nil
	}
	known := make([]string, len(indices))
	for i, index := range indices {
		known[i] = versions[index]
	}
	var patterns []string
	if pattern := versionPattern(name, positive, known, negative); pattern != "" {
		patterns = append(patterns, pattern)
	} else {
		patterns = guardedVersionPatterns(name, positive, known, negative)
	}
	if len(patterns) == 0 {
		return nil
	}
	rule := &fingerlib.Rule{Regexps: &fingerlib.Regexps{Regexp: patterns}}
	if request != "" {
		rule.SendDataStr, rule.Level = request, 2
	}
	return rule
}

func (g *Generator) responses(request string) (positive, negative [][]byte, indices []int) {
	response := func(sample generatorSample) ([]byte, bool) {
		if request == "" {
			return sample.raw, true
		}
		raw, ok := sample.probes[request]
		return raw, ok
	}
	for i, sample := range g.positive {
		if raw, ok := response(sample); ok {
			positive = append(positive, raw)
			indices = append(indices, i)
		}
	}
	for _, sample := range g.negative {
		if raw, ok := response(sample); ok {
			negative = append(negative, raw)
		}
	}
	return positive, negative, indices
}

func versionPattern(name string, positive [][]byte, versions []string, negative [][]byte) string {
	first := -1
	for i, v := range versions {
		if v != "" {
			first = i
			break
		}
	}
	if first < 0 {
		return ""
	}
	raw := string(positive[first])
	for from := 0; from < len(raw); {
		next := strings.Index(raw[from:], versions[first])
		if next < 0 {
			break
		}
		index := from + next
		from = index + len(versions[first])
		pattern := versionPatternAt(raw, index, name)
		if pattern == "" {
			continue
		}
		re, err := regexp.Compile("(?i)" + pattern)
		if err != nil {
			continue
		}
		valid := true
		for i, version := range versions {
			if version == "" {
				continue
			}
			match := re.FindStringSubmatch(string(positive[i]))
			if len(match) < 2 || match[1] != version {
				valid = false
				break
			}
		}
		for _, response := range negative {
			if re.Match(response) {
				valid = false
				break
			}
		}
		if valid {
			return pattern
		}
	}
	return ""
}

func versionPatternAt(raw string, index int, name string) string {
	var pattern string
	// A generator meta tag is stronger than an unscoped product mention.
	for _, loc := range reGenerator.FindAllStringSubmatchIndex(raw, -1) {
		start, end := loc[2], loc[3]
		if start < 0 {
			start, end = loc[4], loc[5]
		}
		if index >= start && index < end && strings.Contains(NormalizeName(raw[start:index]), NormalizeName(name)) {
			return regexp.QuoteMeta(raw[loc[0]:index]) + `(` + versionToken + `|[0-9]+)`
		}
	}
	if headerEnd := strings.Index(raw, "\r\n\r\n"); headerEnd >= 0 && index < headerEnd {
		lineStart := strings.LastIndex(raw[:index], "\n") + 1
		prefix := strings.TrimSpace(raw[lineStart:index])
		if len(prefix) > 48 || !strings.Contains(NormalizeName(prefix), NormalizeName(name)) {
			return ""
		}
		pattern = `(?m)^` + regexp.QuoteMeta(prefix) + `\s*(` + versionToken + `|[0-9]+)`
	} else {
		begin := index - 60
		if begin < 0 {
			begin = 0
		}
		window := raw[begin:index]
		nameIndex := strings.LastIndex(strings.ToLower(window), strings.ToLower(name))
		if nameIndex < 0 {
			return ""
		}
		prefix := window[nameIndex:]
		if len(prefix) > 48 || strings.ContainsAny(prefix, "\r\n<>") {
			return ""
		}
		pattern = regexp.QuoteMeta(strings.TrimSpace(prefix)) + `\s*(` + versionToken + `|[0-9]+)`
	}
	return pattern
}

// Some applications put their release only in asset queries or a footer.
// Learn literal local context, conjoined with a product declaration in ONE
// regex: native body/header/regexp matchers are alternatives, not AND gates.
func guardedVersionPatterns(name string, positive [][]byte, versions []string, negative [][]byte) []string {
	var patterns []string
	seen := map[string]bool{}
	for _, guard := range selectCandidates(positive, negative, name) {
		if guard.weight < 4 || !strings.Contains(NormalizeName(guard.value), NormalizeName(name)) {
			continue
		}
		for i, version := range versions {
			if version == "" {
				continue
			}
			raw := string(positive[i])
			for from := 0; from < len(raw); {
				next := strings.Index(raw[from:], version)
				if next < 0 {
					break
				}
				index := from + next
				from = index + len(version)
				begin := strings.LastIndex(raw[:index], "<")
				if begin < 0 || index-begin > 120 {
					continue
				}
				prefix := regexp.QuoteMeta(raw[begin:index])
				prefix = reSpace.ReplaceAllStringFunc(prefix, func(string) string { return `\s+` })
				pattern := `(?s)` + regexp.QuoteMeta(guard.value) + `.*?` + prefix + `(` + versionToken + `)(?:[^0-9A-Za-z.+-]|$)`
				if seen[pattern] {
					continue
				}
				seen[pattern] = true
				re, err := regexp.Compile("(?i)" + pattern)
				if err != nil {
					continue
				}
				valid := true
				for j, want := range versions {
					match := re.FindStringSubmatch(string(positive[j]))
					if want == "" {
						if match != nil {
							valid = false
						}
						continue
					}
					if len(match) < 2 || match[1] != want {
						valid = false
						break
					}
				}
				for _, raw := range negative {
					if re.Match(raw) {
						valid = false
						break
					}
				}
				if valid {
					patterns = append(patterns, pattern)
					if len(patterns) == 4 {
						return patterns
					}
				}
			}
		}
	}
	return patterns
}
