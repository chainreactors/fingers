package xray

import (
	"testing"

	"github.com/chainreactors/neutron/operators"
	"github.com/chainreactors/neutron/templates"
	"gopkg.in/yaml.v3"
)

func TestCompileNginxTemplate(t *testing.T) {
	yamlStr := `
id: f5-nginx
info:
  name: Nginx
  severity: info
http:
- method: GET
  path:
  - '{{BaseURL}}/'
  matchers:
  - type: dsl
    dsl:
    - icontains(server, "nginx")
  - type: word
    words:
    - Welcome to nginx!
    - <center>nginx
`
	tmpl := &templates.Template{}
	if err := yaml.Unmarshal([]byte(yamlStr), tmpl); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	err := tmpl.Compile(nil)
	t.Logf("Compile error: %v", err)

	for i, req := range tmpl.GetRequests() {
		t.Logf("req[%d] CompiledOperators: %v", i, req.CompiledOperators != nil)
		if req.CompiledOperators != nil {
			for j, m := range req.CompiledOperators.Matchers {
				t.Logf("  matcher[%d] type=%s dsl=%v words=%v", j, m.Type, m.DSL, m.Words)
			}
		}

		// Try manual compile
		t.Logf("req[%d] manual compile...", i)
		compileErr := (&req.Operators).Compile()
		t.Logf("req[%d] manual compile error: %v", i, compileErr)
		if compileErr == nil {
			req.CompiledOperators = &req.Operators
			for j, m := range req.CompiledOperators.Matchers {
				t.Logf("  matcher[%d] type=%s dsl=%v words=%v matcherType=%v", j, m.Type, m.DSL, m.Words, m.GetType())
			}
		}
	}

	// Also test direct matcher compile
	t.Log("\n--- Direct DSL compile ---")
	m := &operators.Matcher{Type: "dsl", DSL: []string{`icontains(server, "nginx")`}}
	err = m.CompileMatchers()
	t.Logf("DSL compile error: %v", err)
}
