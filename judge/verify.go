package judge

import (
	"fmt"
	"sort"
	"strings"

	"github.com/chainreactors/fingers/common"
)

const noneOfThem = "none_of_these" // primary option for pages of no listed product

// protocolFeatures are HTTP features some engines report as fingerprints
// (NormalizeName keys). They must be established by this response's head.
var protocolFeatures = map[string]bool{"hsts": true, "altsvc": true, "http3": true, "http2": true, "poweredby": true, "http基本认证": true}

const (
	maxGroups = 40 // products judged per page
	maxRecall = 8  // recall names judged per page
)

// product is one product claimed for the page: every engine spelling of it
// (frames), or a recall name without a rule hit.
type product struct {
	name    string
	frames  []*common.Framework
	strong  bool // named in a header or cookie: code accepts it, models under-trust it
	feature bool // protocol features have deterministic response-head evidence
}

// Verify is the engine result filter. It folds the spellings of all engines
// into products, asks the provider per product whether it is really in the stack (a
// binary question, so several products can be present) and at which layer (a choice), and which
// product is the page's application. recall names (e.g. fingerprint names
// found in the page) that no rule reported are judged the same way; confirmed
// ones are added to frames. Code decides: a product named in a header or
// cookie is never rejected.
//
// Results are Marks and a layer on frames (see Is, LayerOf, Accepted).
// Frameworks judged before are skipped, so calling Verify again on the same
// frames asks only about new hits.
func Verify(r *Round, frames common.Frameworks, recall []string) {
	page := r.page
	var list []*common.Framework
	judged := map[string]bool{} // keys judged before: not asked again, not recalled again
	for _, f := range frames {
		if f == nil {
			continue
		}
		if Judged(f) {
			judged[NormalizeName(f.Name)] = true
		} else {
			list = append(list, f)
		}
	}
	sort.Slice(list, func(a, b int) bool { return list[a].Name < list[b].Name })
	byKey := map[string]*product{}
	var products []*product
	for _, f := range list {
		key := NormalizeName(f.Name)
		if key == "" {
			continue
		}
		p, ok := byKey[key]
		if !ok {
			if len(products) >= maxGroups {
				continue
			}
			p = &product{name: f.Name, feature: protocolFeatures[key]}
			if p.feature {
				p.strong = protocolPresent(page, key)
			}
			byKey[key] = p
			products = append(products, p)
		}
		p.frames = append(p.frames, f)
		for _, e := range page.Evidence(f.Name) {
			if !p.feature {
				p.strong = p.strong || e == "header" || e == "cookie"
			}
		}
	}
	for _, p := range products {
		sort.SliceStable(p.frames, func(a, b int) bool {
			qa, qb := frameworkQuality(p.frames[a]), frameworkQuality(p.frames[b])
			if qa != qb {
				return qa > qb
			}
			return p.frames[a].Name < p.frames[b].Name
		})
		p.name = p.frames[0].Name
	}
	recalled := 0
	for _, name := range recall {
		key := NormalizeName(name)
		if _, ok := byKey[key]; ok || key == "" || judged[key] {
			continue
		}
		if recalled >= maxRecall {
			break
		}
		p := &product{name: name}
		byKey[key] = p
		products = append(products, p)
		recalled++
	}
	if len(products) == 0 {
		return
	}

	type answer struct {
		present  float64
		answered bool
		layer    Layer
	}
	answers := make([]answer, len(products))
	var primary string
	primaryOpts := map[string]string{noneOfThem: "The page belongs to none of the listed products, e.g. a custom-built site"}
	for i, p := range products {
		i, name := i, p.name
		primaryOpts[name] = ""
		r.Add(fmt.Sprintf("is_%d", i), BinaryWith(fmt.Sprintf("Is `%s` part of the software stack that produced this HTTP response "+
			"(seen in its headers, cookies, asset paths, page structure or title), rather than only mentioned in the page text? "+
			"A packaged browser-side or static web application counts even without a login or server backend. "+
			"On documentation, README or tutorial pages, the product being documented does not count as running; distinguish it from the documentation generator.", name),
			name+" served, generated or is loaded by this response",
			name+" only appears in the page's text, or is not present"),
			func(a Answer) { answers[i].present, answers[i].answered = a.Yes, true })
		r.Add(fmt.Sprintf("layer_%d", i), Choice(fmt.Sprintf("What role does `%s` play in producing this HTTP response?", name), layerCriteria),
			func(a Answer) { answers[i].layer = Layer(a.Choice) })
	}
	r.Add("primary", Choice("Which listed product is the main application this page belongs to "+
		"(the product whose login, console or content this is), as opposed to servers, frameworks and libraries underneath it?", primaryOpts),
		func(a Answer) {
			if a.Choice != noneOfThem {
				primary = a.Choice
			}
		})

	r.Done(func() {
		for i, p := range products {
			a := answers[i]
			rejected := !p.strong && (p.feature || a.answered && (a.layer == LayerNotPresent || a.present < r.judge.Threshold))
			if p.frames == nil { // recall: added only when the provider confirms it
				if !a.answered || rejected {
					continue
				}
				f := common.NewFramework(p.name, common.FrameFromGUESS)
				mark(f, Recalled)
				frames.Add(f)
				p.frames = []*common.Framework{f}
			}
			for j, f := range p.frames {
				setLayer(f, a.layer)
				if rejected {
					mark(f, Rejected)
				}
				if j > 0 {
					mark(f, Duplicate)
				}
			}
			if p.name == primary && !rejected {
				mark(p.frames[0], Primary)
			}
		}
	})
}

func protocolPresent(p *Page, key string) bool {
	switch key {
	case "hsts":
		return p.Headers["Strict-Transport-Security"] != ""
	case "altsvc":
		return p.Headers["Alt-Svc"] != ""
	case "poweredby":
		return p.Headers["X-Powered-By"] != ""
	case "http2":
		return strings.HasPrefix(string(p.raw), "HTTP/2") || strings.Contains(strings.ToLower(p.Headers["Alt-Svc"]), "h2=")
	case "http3":
		return strings.HasPrefix(string(p.raw), "HTTP/3") || strings.Contains(strings.ToLower(p.Headers["Alt-Svc"]), "h3=")
	case "http基本认证":
		for _, challenge := range strings.Split(p.Headers["Www-Authenticate"], ",") {
			words := strings.Fields(challenge)
			if len(words) > 0 && strings.EqualFold(words[0], "Basic") {
				return true
			}
		}
	}
	return false
}

// Prefer a representative that already carries a version and useful source
// metadata, since duplicate spellings are hidden from the accepted result.
func frameworkQuality(f *common.Framework) int {
	quality := len(f.Froms)
	if f.Attributes != nil {
		if f.Version != "" {
			quality += 100
		}
		if f.Vendor != "" {
			quality += 10
		}
	}
	if f.MatchDetail != nil {
		quality++
	}
	return quality
}
