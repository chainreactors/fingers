//go:build !goregexp

package fingers

import re2 "github.com/wasilibs/go-re2"

func compileRegexp(s string) (CompiledRegexp, error) {
	return re2.Compile(s)
}
