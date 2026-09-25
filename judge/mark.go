package judge

import (
	"strings"

	"github.com/chainreactors/fingers/common"
)

// Mark is a judgement written onto a framework. Marks live in Framework.Tags
// as "judge:<mark>" (and the layer as "judge:layer=<layer>"), so they serialize
// with every existing output and need no new field; read them with Is and
// LayerOf rather than parsing tags.
type Mark string

const (
	Rejected  Mark = "rejected" // not in the stack, or only mentioned in text: a false positive
	Duplicate Mark = "dup"      // another engine's spelling of a product already in the result
	Primary   Mark = "primary"  // the application the page belongs to
	Recalled  Mark = "recall"   // missed by the rules, found by name and confirmed by the judge
)

// TagPrefix starts every tag this package writes.
const TagPrefix = "judge:"

const layerTag = TagPrefix + "layer="

// Tag is the Framework.Tags spelling of m.
func (m Mark) Tag() string { return TagPrefix + string(m) }

// Is reports whether f carries m.
func Is(f *common.Framework, m Mark) bool { return f != nil && f.HasTag(m.Tag()) }

// LayerOf returns the layer f was judged to be at, or "" if f was not judged.
func LayerOf(f *common.Framework) Layer {
	if f == nil {
		return ""
	}
	for _, t := range f.Tags {
		if strings.HasPrefix(t, layerTag) {
			return Layer(strings.TrimPrefix(t, layerTag))
		}
	}
	return ""
}

// Judged reports whether f went through Verify.
func Judged(f *common.Framework) bool { return LayerOf(f) != "" }

func mark(f *common.Framework, m Mark) { f.AddTag(m.Tag()) }

func setLayer(f *common.Framework, l Layer) {
	if l != "" && LayerOf(f) == "" {
		f.AddTag(layerTag + string(l))
	}
}

// PrimaryOf returns the framework marked Primary.
func PrimaryOf(frames common.Frameworks) *common.Framework {
	for _, f := range frames {
		if Is(f, Primary) {
			return f
		}
	}
	return nil
}

// Accepted returns frames without Rejected hits and Duplicate spellings: one
// framework per product that is really there.
func Accepted(frames common.Frameworks) common.Frameworks {
	out := common.Frameworks{}
	for k, f := range frames {
		if f != nil && !Is(f, Rejected) && !Is(f, Duplicate) {
			out[k] = f
		}
	}
	return out
}
