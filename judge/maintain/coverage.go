package maintain

import (
	"context"
	"fmt"
	"sort"

	"github.com/chainreactors/fingers/judge"
	"github.com/chainreactors/fingers/judge/internal/evidence"
	"github.com/chainreactors/utils/jev"
)

// Coverage options: what the samples of one page show beside the products
// the rules report on them.
const (
	CoverageExplained = "explained"   // holds: the reported products account for the page
	CoverageCustom    = "custom_site" // holds: content one organization wrote; no packaged product to fingerprint
	CoverageMissing   = "missing"     // refuted: the stock page of a packaged product the rules miss
)

const maxCoverageSamples = 3

// Coverage rules on the claim that the products the rules report account
// for samples: responses of one page, ideally from unrelated hosts. It is
// the offline counterpart of presence claims. A Refuted ruling
// (CoverageMissing) is a missed product for a person to name, e.g. from
// Cluster candidates; the provider never names one, and reported
// are the claim under review, never options to pick from.
func coverage(ctx context.Context, j *judge.Judge, samples [][]byte, reported []string) (jev.Ruling, jev.Outcome, error) {
	var pages []*evidence.Page
	for _, raw := range samples {
		if len(pages) == maxCoverageSamples {
			break
		}
		p, err := evidence.NewPage(raw)
		if err != nil {
			return jev.Ruling{}, jev.Insufficient, err
		}
		pages = append(pages, p)
	}
	if len(pages) == 0 {
		return jev.Ruling{}, jev.Insufficient, fmt.Errorf("coverage: no samples")
	}
	names := append([]string{}, reported...)
	sort.Strings(names)
	state := map[string]interface{}{"samples": pages, "reported": names}
	if len(pages) > 1 {
		state["note"] = "the samples are the same page served by unrelated hosts: a page many unrelated operators serve alike is usually a packaged product, not content one organization wrote"
	}
	claim := jev.Claim{
		Statement: "`reported` lists the products fingerprint rules report on these `samples`. " +
			"Claim: they account for the page, that is, the page is not the stock interface of a packaged product missing from `reported`. " +
			"A stock interface is a product's own login, console, default, error or application page, " +
			"which looks the same on every deployment of it except for branding, host names and data. " +
			"Servers, CDNs, frameworks, libraries and databases underneath an application do not account for the application's own page.",
		Options: map[string]jev.Option{
			jev.OptionInsufficient: {Description: "The evidence does not decide the claim.", Outcome: jev.Insufficient},
			CoverageExplained:      {Description: "The page is the stock interface of a product in `reported`, or shows no packaged product beyond them, such as a bare server default or error page.", Outcome: jev.Holds},
			CoverageCustom:         {Description: "Content one organization wrote for its own purpose: articles, company pages, shops, forums, custom-built portals.", Outcome: jev.Holds},
			CoverageMissing:        {Description: "The page is the stock interface of a packaged product that is not in `reported`.", Outcome: jev.Refuted},
		},
	}
	rulings, err := jev.Judge(ctx, j.Provider, state, map[string]jev.Claim{"coverage": claim})
	if err != nil {
		return jev.Ruling{}, jev.Insufficient, err
	}
	return rulings["coverage"], claim.Resolve(rulings["coverage"], j.MinConfidence), nil
}
