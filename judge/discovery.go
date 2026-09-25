package judge

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/chainreactors/fingers/common"
)

var (
	nameWords   = regexp.MustCompile(`[A-Z][A-Za-z0-9!+._]{2,}(?:[ -][A-Z][A-Za-z0-9!+._]{2,}){0,2}|[\p{Han}]{2,20}`)
	nameVersion = regexp.MustCompile(`(?i)[/\s]+[vV]?(?:` + versionToken + `|[0-9]+)\s*$`)
)

// IsUnknownProduct reports whether this looks like a reusable product page
// with no identified product. Pass accepted fingerprints from Verify or
// Refine; known infrastructure alone does not identify an application.
func (j *Judge) IsUnknownProduct(ctx context.Context, raw []byte, accepted common.Frameworks) (bool, error) {
	kind, generic, err := j.Classify(ctx, raw)
	if err != nil || !generic {
		return false, err
	}
	for _, f := range accepted {
		if Is(f, Rejected) || Is(f, Duplicate) {
			continue
		}
		switch LayerOf(f) {
		case LayerApplication, LayerDevice:
			return false, nil
		case LayerServer, LayerCDN:
			if kind == KindDefault || kind == KindError || kind == KindDirListing {
				return false, nil
			}
		}
	}
	return true, nil
}

// SuggestNames returns product names supported by page evidence. Candidates
// are extracted from this response, including visible body text; no name is
// invented by the provider or drawn from an installed fingerprint catalog.
func (j *Judge) SuggestNames(ctx context.Context, raw []byte) ([]string, error) {
	p, err := NewPage(raw)
	if err != nil {
		return nil, err
	}
	candidates := pageNames(p)
	if len(candidates) == 0 {
		return nil, nil
	}
	r := p.Round()
	prob := make([]float64, len(candidates))
	for i, name := range candidates {
		i, name := i, name
		r.Add(fmt.Sprintf("name_%d", i), BinaryWith(
			fmt.Sprintf("Is `%s` the product whose own interface, login, console or default page this response shows, rather than infrastructure underneath another product, generic wording or an article mention?", name),
			name+" owns this page",
			name+" is infrastructure or merely mentioned"),
			func(a Answer) { prob[i] = a.Yes })
	}
	if err := r.Ask(ctx, j); err != nil {
		return nil, err
	}
	var indices []int
	for i, v := range prob {
		if v >= j.Threshold {
			indices = append(indices, i)
		}
	}
	sort.SliceStable(indices, func(a, b int) bool { return prob[indices[a]] > prob[indices[b]] })
	out := make([]string, 0, len(indices))
	for _, i := range indices {
		out = append(out, candidates[i])
	}
	return out, nil
}

func pageNames(p *Page) []string {
	type candidate struct {
		name   string
		weight int
	}
	byKey := map[string]candidate{}
	add := func(text string, weight int) {
		text = strings.Trim(strings.TrimSpace(nameVersion.ReplaceAllString(clean(text), "")), "-:|/ ")
		if text == "" || utf8.RuneCountInString(text) > 40 || !usableKey(strings.ToLower(text)) {
			return
		}
		key := NormalizeName(text)
		if key == "" || genericName(key) {
			return
		}
		if prev, ok := byKey[key]; !ok || weight > prev.weight {
			byKey[key] = candidate{text, weight}
		}
	}
	add(p.Generator, 5)
	for k, v := range p.Headers {
		if strings.HasPrefix(k, "X-") || k == "Server" || k == "X-Powered-By" || k == "Product" {
			add(strings.Split(v, "/")[0], 4)
		}
	}
	for _, part := range strings.FieldsFunc(p.Title, func(r rune) bool { return r == '|' || r == '-' || r == ':' || r == '–' }) {
		add(part, 4)
	}
	for _, asset := range append(append([]string(nil), p.Scripts...), p.Styles...) {
		for _, word := range strings.FieldsFunc(asset, func(r rune) bool { return r == '/' || r == '_' }) {
			add(word, 2)
		}
	}
	for _, segment := range strings.FieldsFunc(p.Text, func(r rune) bool { return r == '.' || r == ':' || r == '。' || r == '：' || r == '|' || r == '，' }) {
		for _, match := range nameWords.FindAllString(segment, 20) {
			add(match, 1)
		}
	}
	list := make([]candidate, 0, len(byKey))
	for _, c := range byKey {
		list = append(list, c)
	}
	sort.Slice(list, func(a, b int) bool {
		if list[a].weight != list[b].weight {
			return list[a].weight > list[b].weight
		}
		return list[a].name < list[b].name
	})
	if len(list) > 20 {
		list = list[:20]
	}
	out := make([]string, len(list))
	for i, c := range list {
		out[i] = c.name
	}
	return out
}

func genericName(key string) bool {
	switch key {
	case "login", "signin", "welcome", "dashboard", "admin", "console", "home", "index", "server", "error", "notfound", "password", "username", "management", "system", "登录", "首页", "管理", "用户", "密码", "控制台":
		return true
	}
	return false
}
