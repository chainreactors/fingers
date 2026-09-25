package jev

import (
	"fmt"
	"sort"

	"github.com/chainreactors/fingers/common"
)

// Threshold is the Noul at or above which Jev's "yes" counts. Tuned for DefaultModel.
var Threshold = 0.5

// Tags written onto frameworks by Verify. Frameworks are annotated in place,
// never removed: callers decide whether to drop what Jev rejected.
const (
	TagRejected = "jev:rejected" // rule hit Jev judged absent or only mentioned in text
	TagDup      = "jev:dup"      // another spelling of a product already in frames
	TagPrimary  = "jev:primary"  // the application the page belongs to
	TagRecall   = "jev:recall"   // added: no rule hit, found by name and confirmed by Jev
	TagLayer    = "jev:layer="   // prefix; followed by a Layer
)

// NoneOfThem is the primary option for pages that belong to no listed product.
const NoneOfThem = "none_of_these"

// ProtocolFeatures are HTTP features some engines report as fingerprints
// (NormalizeName keys). They are facts of the response head: never rejected.
var ProtocolFeatures = map[string]bool{"hsts": true, "altsvc": true, "http3": true, "http2": true, "poweredby": true, "http基本认证": true}

const (
	maxGroups = 40 // products judged per page
	maxRecall = 8  // recall names judged per page
)

// product is one product claimed for the page: every engine spelling of it
// (frames), or a recall name without a rule hit.
type product struct {
	name   string
	frames []*common.Framework
	strong bool // named in a header or cookie: code accepts it, Jev under-trusts it
}

// Verify is the engine result filter. It folds the spellings of all engines
// into products, asks Jev per product whether it is really in the stack (a
// Noul, so several products can be present) and at which layer, and which
// product is the page's application. recall names (e.g. fingerprint names
// found in the page) that no rule reported are judged the same way; confirmed
// ones are added to frames. Code decides: a product named in a header or
// cookie is never rejected.
func Verify(r *Round, frames common.Frameworks, recall []string) {
	page := r.page
	list := frames.List()
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
			p = &product{name: f.Name, strong: ProtocolFeatures[key]}
			byKey[key] = p
			products = append(products, p)
		}
		p.frames = append(p.frames, f)
		for _, e := range page.Evidence(f.Name) {
			p.strong = p.strong || e == "header" || e == "cookie"
		}
	}
	recalled := 0
	for _, name := range recall {
		key := NormalizeName(name)
		if _, ok := byKey[key]; ok || key == "" {
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
	primaryOpts := map[string]interface{}{NoneOfThem: "The page belongs to none of the listed products, e.g. a custom-built site"}
	for i, p := range products {
		i, name := i, p.name
		primaryOpts[name] = nil
		r.Add(fmt.Sprintf("is_%d", i), Question{
			Type: "noul",
			Instructions: fmt.Sprintf("Is `%s` part of the software stack that produced this HTTP response "+
				"(seen in its headers, cookies, asset paths, page structure or title), rather than only mentioned in the page text?", name),
			Criteria: map[string]string{
				"true":  name + " served, generated or is loaded by this response",
				"false": name + " only appears in the page's text, or is not present",
			},
		}, func(a Answer) { answers[i].present, answers[i].answered = a.Noul, true })
		r.Add(fmt.Sprintf("layer_%d", i), Choice(fmt.Sprintf("What role does `%s` play in producing this HTTP response?", name), LayerCriteria),
			func(a Answer) { answers[i].layer = Layer(a.Choice) })
	}
	r.Add("primary", Choice("Which listed product is the main application this page belongs to "+
		"(the product whose login, console or content this is), as opposed to servers, frameworks and libraries underneath it?", primaryOpts),
		func(a Answer) {
			if a.Choice != NoneOfThem {
				primary = a.Choice
			}
		})

	r.Done(func() {
		for i, p := range products {
			a := answers[i]
			rejected := !p.strong && a.answered && (a.layer == LayerNotPresent || a.present < Threshold)
			if p.frames == nil { // recall: added only when Jev confirms it
				if !a.answered || rejected {
					continue
				}
				f := common.NewFramework(p.name, common.FrameFromGUESS)
				f.AddTag(TagRecall)
				frames.Add(f)
				p.frames = []*common.Framework{f}
			}
			for j, f := range p.frames {
				if a.layer != "" {
					f.AddTag(TagLayer + string(a.layer))
				}
				if rejected {
					f.AddTag(TagRejected)
				}
				if j > 0 {
					f.AddTag(TagDup)
				}
			}
			if p.name == primary && !rejected {
				p.frames[0].AddTag(TagPrimary)
			}
		}
	})
}
