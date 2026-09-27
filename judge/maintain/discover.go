package maintain

import (
	"context"
	"regexp"
	"sort"
	"strings"

	"github.com/chainreactors/fingers/common"
	"github.com/chainreactors/fingers/judge"
	"github.com/chainreactors/fingers/judge/internal/evidence"
	"github.com/chainreactors/utils/jev"
)

// Sample is one scanned response for discovery.
type Sample struct {
	ID, Host string
	Raw      []byte
	Accepted common.Frameworks // Inspect(Raw).Accepted() for Raw
}

// Cluster is one page served by several hosts, as Discover found it.
type Cluster struct {
	Samples []string `json:"samples"`
	Hosts   int      `json:"hosts"`
	// Reported are the products the samples' rules report.
	Reported []string `json:"reported,omitempty"`
	// Coverage is the ruling on the claim that Reported account for the
	// page: Refuted (CoverageMissing) marks a missed product.
	Coverage jev.Ruling  `json:"coverage"`
	Outcome  jev.Outcome `json:"outcome"`
	// Candidates are names code finds in the samples, for the person who
	// names a missed product; they are never offered to the provider.
	Candidates []string `json:"candidates,omitempty"`
}

// MinSimilarity is the structural overlap (Jaccard of asset paths, form
// fields, cookie and custom header names, generator and title words) at
// which two pages are one page. On the 2026-09-26 corpus it links 52 of 54
// cross-host pairs of one product and 22 of 2278 other pairs, mostly stock
// pages of one known product.
const MinSimilarity = 0.4

// Discover clusters samples that are one page on different hosts and, once
// per cluster of at least minHosts hosts, evaluates whether
// the products the rules report account for it. Code does the clustering
// and the host count: a page served the same by unrelated hosts is what a
// fingerprint can describe.
func Discover(ctx context.Context, j *judge.Judge, samples []Sample, minHosts int) ([]*Cluster, error) {
	pages := make([]map[string]bool, len(samples))
	for i, s := range samples {
		p, err := evidence.NewPage(s.Raw)
		if err != nil {
			continue
		}
		pages[i] = features(p)
	}
	parent := make([]int, len(samples))
	for i := range parent {
		parent[i] = i
	}
	var find func(int) int
	find = func(i int) int {
		if parent[i] != i {
			parent[i] = find(parent[i])
		}
		return parent[i]
	}
	for a := range samples {
		for b := a + 1; b < len(samples); b++ {
			if pages[a] != nil && pages[b] != nil && jaccard(pages[a], pages[b]) >= MinSimilarity {
				parent[find(a)] = find(b)
			}
		}
	}
	groups := map[int][]Sample{}
	var roots []int
	for i, s := range samples {
		if pages[i] == nil {
			continue
		}
		r := find(i)
		if groups[r] == nil {
			roots = append(roots, r)
		}
		groups[r] = append(groups[r], s)
	}
	var out []*Cluster
	for _, r := range roots {
		c := &Cluster{}
		var raws [][]byte
		hosts := map[string]bool{}
		for _, s := range groups[r] {
			c.Samples = append(c.Samples, s.ID)
			if !hosts[s.Host] {
				hosts[s.Host] = true
				raws = append(raws, s.Raw)
			}
		}
		c.Hosts = len(hosts)
		if c.Hosts < minHosts {
			continue
		}
		c.Reported = reported(groups[r])
		ruling, outcome, err := coverage(ctx, j, raws, c.Reported)
		if err != nil {
			return out, err
		}
		c.Coverage, c.Outcome = ruling, outcome
		c.Candidates = candidates(raws)
		out = append(out, c)
	}
	sort.SliceStable(out, func(a, b int) bool { return out[a].Hosts > out[b].Hosts })
	return out, nil
}

// reported are the products any sample reports, one spelling each.
func reported(samples []Sample) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range samples {
		for _, f := range s.Accepted {
			if key := judge.NormalizeName(f.Name); key != "" && !seen[key] {
				seen[key] = true
				out = append(out, f.Name)
			}
		}
	}
	sort.Strings(out)
	return out
}

const maxCandidates = 20

// candidates are the names that occur in two samples (or the only one),
// most telling source first: generator meta, product headers, title parts,
// asset path words, then capitalized words of the visible text.
func candidates(raws [][]byte) []string {
	need := 2
	if len(raws) < need {
		need = len(raws)
	}
	count := map[string]int{}
	label := map[string]string{}
	var order []string
	for _, raw := range raws {
		p, err := evidence.NewPage(raw)
		if err != nil {
			continue
		}
		seen := map[string]bool{}
		for _, n := range evidence.Names(p.Generator, p.Title, p.Text, p.Headers, append(append([]string(nil), p.Scripts...), p.Styles...)) {
			key := judge.NormalizeName(n)
			if seen[key] {
				continue
			}
			seen[key] = true
			if count[key] == 0 {
				label[key] = n
				order = append(order, key)
			}
			count[key]++
		}
	}
	var out []string
	for _, key := range order {
		if count[key] >= need && len(out) < maxCandidates {
			out = append(out, label[key])
		}
	}
	return out
}

var reVolatile = regexp.MustCompile(`[0-9a-f]{6,}|[0-9]+`)

// commonHeaders are X- headers any stack sets: they tell pages of one
// product apart from nothing.
var commonHeaders = map[string]bool{
	"x-content-type-options": true, "x-frame-options": true, "x-xss-protection": true, "x-request-id": true,
	"x-download-options": true, "x-permitted-cross-domain-policies": true, "x-dns-prefetch-control": true,
	"x-robots-tag": true, "x-cache": true, "x-served-by": true, "x-forwarded-for": true, "x-forwarded-proto": true,
}

// features are the structural traits of a page that its deployments share:
// asset paths without queries or hashes, form fields, cookie and custom
// header names, the generator and title words.
func features(p *evidence.Page) map[string]bool {
	out := map[string]bool{}
	fold := func(s string) string {
		if i := strings.IndexAny(s, "?#"); i >= 0 {
			s = s[:i]
		}
		return reVolatile.ReplaceAllString(strings.ToLower(s), "")
	}
	for _, x := range append(append([]string(nil), p.Scripts...), p.Styles...) {
		out["asset:"+fold(x)] = true
	}
	for _, x := range p.Forms {
		out["form:"+strings.ToLower(x)] = true
	}
	for _, x := range p.Cookies {
		out["cookie:"+fold(x)] = true
	}
	for k := range p.Headers {
		if k := strings.ToLower(k); strings.HasPrefix(k, "x-") && !commonHeaders[k] {
			out["header:"+k] = true
		}
	}
	if p.Generator != "" {
		out["generator:"+judge.NormalizeName(reVolatile.ReplaceAllString(p.Generator, ""))] = true
	}
	for _, w := range strings.FieldsFunc(strings.ToLower(p.Title), func(r rune) bool { return strings.ContainsRune(" -|:.·–", r) }) {
		if len(w) > 2 {
			out["title:"+w] = true
		}
	}
	return out
}

func jaccard(a, b map[string]bool) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	n := 0
	for k := range a {
		if b[k] {
			n++
		}
	}
	return float64(n) / float64(len(a)+len(b)-n)
}
