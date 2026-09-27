// Package re2 switches the fingers rule engine to RE2
// (github.com/wasilibs/go-re2), which matches large rule sets faster than
// the standard library. Import it for its side effect:
//
//	import _ "github.com/chainreactors/fingers/re2"
//
// It is a separate module because RE2 needs Go 1.24, while fingers itself
// supports Go 1.17. Build with -tags re2_cgo to use a native libre2.
package re2

import (
	"github.com/chainreactors/fingers/fingers"
	re2 "github.com/wasilibs/go-re2"
)

func init() { fingers.RegexpCompiler = Compile }

// Compile compiles expr with RE2.
func Compile(expr string) (fingers.CompiledRegexp, error) { return re2.Compile(expr) }
