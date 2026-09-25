package fingers

import "regexp"

type CompiledRegexp interface {
	FindSubmatch(b []byte) [][]byte
	FindAllString(s string, n int) []string
	Match(b []byte) bool
	String() string
}

// RegexpCompiler compiles the regexps of fingerprint rules. It is the
// standard library's by default; importing github.com/chainreactors/fingers/re2
// switches it to RE2, which is faster on large rule sets. Set it before
// fingerprints are loaded.
var RegexpCompiler = func(expr string) (CompiledRegexp, error) {
	return regexp.Compile(expr)
}

func compileRegexp(s string) (CompiledRegexp, error) { return RegexpCompiler(s) }
