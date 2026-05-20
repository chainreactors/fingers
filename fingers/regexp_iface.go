package fingers

type CompiledRegexp interface {
	FindSubmatch(b []byte) [][]byte
	FindAllString(s string, n int) []string
	Match(b []byte) bool
	String() string
}
