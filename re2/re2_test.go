package re2

import (
	"regexp"
	"testing"

	fingerlib "github.com/chainreactors/fingers"
	"github.com/chainreactors/fingers/fingers"
	re2 "github.com/wasilibs/go-re2"
)

const nginx = "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n\r\n<title>Welcome to nginx!</title>"

func TestEngineUsesRE2(t *testing.T) {
	if _, err := fingers.RegexpCompiler("a+"); err != nil {
		t.Fatal(err)
	}
	if c, _ := fingers.RegexpCompiler("a+"); c == nil {
		t.Fatal("no compiler")
	} else if _, ok := c.(*re2.Regexp); !ok {
		t.Fatalf("compiler is %T, want *re2.Regexp", c)
	}
	engine, err := fingerlib.NewEngine(fingerlib.FingersEngine)
	if err != nil {
		t.Fatal(err)
	}
	frames, err := engine.DetectContent([]byte(nginx))
	if err != nil || frames["nginx"] == nil {
		t.Fatalf("frames %v, %v", frames, err)
	}
}

// BenchmarkDetect compares the fingers engine on the standard library and RE2.
func BenchmarkDetect(b *testing.B) {
	for _, c := range []struct {
		name    string
		compile func(string) (fingers.CompiledRegexp, error)
	}{
		{"regexp", func(s string) (fingers.CompiledRegexp, error) { return regexp.Compile(s) }},
		{"re2", Compile},
	} {
		b.Run(c.name, func(b *testing.B) {
			fingers.RegexpCompiler = c.compile
			defer func() { fingers.RegexpCompiler = Compile }()
			engine, err := fingerlib.NewEngine(fingerlib.FingersEngine)
			if err != nil {
				b.Fatal(err)
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				engine.DetectContent([]byte(nginx))
			}
		})
	}
}
