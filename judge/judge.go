package judge

import (
	"context"
	"fmt"
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

// ready rejects a canceled context or an invalid configuration up front.
func (j *Judge) ready(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if math.IsNaN(j.MinConfidence) || j.MinConfidence < 0 || j.MinConfidence > 1 {
		return fmt.Errorf("judge: invalid MinConfidence %v", j.MinConfidence)
	}
	return nil
}

// insufficientDescription describes the abstention every claim offers.
const insufficientDescription = "The evidence decides neither way."
