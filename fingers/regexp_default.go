//go:build goregexp

package fingers

import "regexp"

func compileRegexp(s string) (CompiledRegexp, error) {
	return regexp.Compile(s)
}
