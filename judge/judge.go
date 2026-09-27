package judge

import (
	"context"
	"math"

	"github.com/chainreactors/fingers/judge/internal/evidence"
	"github.com/chainreactors/utils/jev"
)

// Judge reviews fingerprint hits through jev claims. Configure it before
// sharing it across a scan. Caching, request accounting and rate limiting
// wrap its Provider (see jev.Cached).
type Judge struct {
	Provider         jev.Provider
	MinConfidence    float64 // below it a ruling resolves to Insufficient
	DropInsufficient bool    // also reject hits the evidence decides neither way
}

// New reviews hits with p at jev.DefaultMinConfidence.
func New(p jev.Provider) *Judge {
	return &Judge{Provider: p, MinConfidence: jev.DefaultMinConfidence}
}

func NormalizeName(name string) string { return evidence.NormalizeName(name) }

func (j *Judge) judge(ctx context.Context, state interface{}, claims map[string]jev.Claim) (map[string]jev.Ruling, error) {
	return jev.Judge(ctx, j.Provider, state, claims)
}

// validRuling checks a single claim and ruling, including code-built ones.
func validRuling(c jev.Claim, r jev.Ruling) error {
	return jev.ValidateRulings(map[string]jev.Claim{"claim": c}, map[string]jev.Ruling{"claim": r})
}

// insufficientDescription describes the abstention every claim offers.
const insufficientDescription = "The evidence decides neither way."

func probability(v float64) bool {
	return !math.IsNaN(v) && !math.IsInf(v, 0) && v >= 0 && v <= 1
}
