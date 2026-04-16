// fingerverify validates semantic equivalence between a CyberHub xray-style
// fingerprint YAML (rules + expression DSL) and a fingers-native fingerprint
// YAML by generating mock HTTP responses and comparing how each engine matches.
//
// Usage:
//
//	fingerverify --source <xray.yml> --target <fingers.yaml> [--json] [-v]
//	fingerverify <xray.yml> <fingers.yaml> [--json] [-v]
//
// Exits 0 on successful evaluation (consistent or divergent). Non-zero only on
// tool-level errors (I/O, YAML parse).
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/Knetic/govaluate"
	"github.com/chainreactors/fingers/fingers"
	"gopkg.in/yaml.v3"
)

// helperFunctions provides the subset of xray/nuclei DSL helpers needed for
// fingerprint expression evaluation. Kept self-contained to avoid pulling
// neutron/common (which transitively imports govalidator and panics on init
// under recent Go versions).
func helperFunctions() map[string]govaluate.ExpressionFunction {
	asStr := func(v interface{}) string { return fmt.Sprintf("%v", v) }
	return map[string]govaluate.ExpressionFunction{
		"contains": func(args ...interface{}) (interface{}, error) {
			if len(args) < 2 {
				return false, nil
			}
			return strings.Contains(asStr(args[0]), asStr(args[1])), nil
		},
		"icontains": func(args ...interface{}) (interface{}, error) {
			if len(args) < 2 {
				return false, nil
			}
			return strings.Contains(strings.ToLower(asStr(args[0])), strings.ToLower(asStr(args[1]))), nil
		},
		"starts_with": func(args ...interface{}) (interface{}, error) {
			if len(args) < 2 {
				return false, nil
			}
			return strings.HasPrefix(asStr(args[0]), asStr(args[1])), nil
		},
		"ends_with": func(args ...interface{}) (interface{}, error) {
			if len(args) < 2 {
				return false, nil
			}
			return strings.HasSuffix(asStr(args[0]), asStr(args[1])), nil
		},
		"regex": func(args ...interface{}) (interface{}, error) {
			if len(args) < 2 {
				return false, nil
			}
			pattern := asStr(args[0])
			target := asStr(args[1])
			re, err := regexp.Compile(pattern)
			if err != nil {
				return false, nil
			}
			return re.MatchString(target), nil
		},
		"len": func(args ...interface{}) (interface{}, error) {
			if len(args) < 1 {
				return float64(0), nil
			}
			return float64(len(asStr(args[0]))), nil
		},
	}
}

// ---------------------------------------------------------------------------
// Source fingerprint schema (xray-style as stored in CyberHub)
// ---------------------------------------------------------------------------

type sourceFPRequest struct {
	Method          string            `yaml:"method"`
	Path            string            `yaml:"path"`
	Headers         map[string]string `yaml:"headers"`
	Body            string            `yaml:"body"`
	FollowRedirects bool              `yaml:"follow_redirects"`
	Cache           bool              `yaml:"cache"`
}

type sourceFPRule struct {
	Request    *sourceFPRequest  `yaml:"request,omitempty"`
	Expression string            `yaml:"expression"`
	Output     map[string]string `yaml:"output,omitempty"`
}

type sourceFP struct {
	Name       string                  `yaml:"name"`
	Detail     map[string]interface{}  `yaml:"detail"`
	Transport  string                  `yaml:"transport"`
	Rules      map[string]sourceFPRule `yaml:"rules"`
	Expression string                  `yaml:"expression"`
}

// ---------------------------------------------------------------------------
// Mock response + report
// ---------------------------------------------------------------------------

type mockResponse struct {
	Name       string            `json:"name"`
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body"`
}

// buildRawContent builds an HTTP-1.1 wire dump suitable for fingers.NewContent.
func (m mockResponse) buildRawContent() []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/1.1 %d OK\r\n", m.StatusCode)
	// Keep deterministic header order for reproducibility.
	keys := make([]string, 0, len(m.Headers))
	for k := range m.Headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "%s: %s\r\n", k, m.Headers[k])
	}
	b.WriteString("\r\n")
	b.WriteString(m.Body)
	return []byte(b.String())
}

type caseResult struct {
	MockName     string        `json:"mock_name"`
	Mock         *mockResponse `json:"mock,omitempty"`
	SourceResult bool          `json:"source_result"`
	TargetResult bool          `json:"target_result"`
	Consistent   bool          `json:"consistent"`
	SourceError  string        `json:"source_error,omitempty"`
	TargetError  string        `json:"target_error,omitempty"`
	TargetHit    string        `json:"target_hit,omitempty"` // which finger name matched
}

type fingerResult struct {
	Name       string       `json:"name"`
	Cases      []caseResult `json:"cases"`
	Consistent bool         `json:"consistent"`
}

type report struct {
	SourcePath    string         `json:"source_path"`
	TargetPath    string         `json:"target_path"`
	SourceName    string         `json:"source_name"`
	TopExpression string         `json:"top_expression"`
	TargetCount   int            `json:"target_count"`
	TargetFingers []string       `json:"target_fingers"`
	Results       []fingerResult `json:"results"`
	TotalCases    int            `json:"total_cases"`
	Passed        int            `json:"passed"`
	Failed        int            `json:"failed"`
	Consistent    bool           `json:"consistent"`
	Warnings      []string       `json:"warnings,omitempty"`
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

func main() {
	var (
		sourcePath string
		targetPath string
		jsonOut    bool
		verbose    bool
	)
	flag.StringVar(&sourcePath, "source", "", "path to xray-style fingerprint YAML")
	flag.StringVar(&targetPath, "target", "", "path to fingers native fingerprint YAML")
	flag.BoolVar(&jsonOut, "json", false, "emit JSON report")
	flag.BoolVar(&verbose, "v", false, "verbose output (include mock dumps)")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage:")
		fmt.Fprintln(os.Stderr, "  fingerverify --source <xray.yml> --target <fingers.yaml> [--json] [-v]")
		fmt.Fprintln(os.Stderr, "  fingerverify <xray.yml> <fingers.yaml> [--json] [-v]")
		flag.PrintDefaults()
	}
	flag.Parse()

	if sourcePath == "" && flag.NArg() >= 1 {
		sourcePath = flag.Arg(0)
	}
	if targetPath == "" && flag.NArg() >= 2 {
		targetPath = flag.Arg(1)
	}
	if sourcePath == "" || targetPath == "" {
		flag.Usage()
		os.Exit(2)
	}

	src, err := loadSource(sourcePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load source: %v\n", err)
		os.Exit(1)
	}
	tgt, err := loadTarget(targetPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load target: %v\n", err)
		os.Exit(1)
	}

	rep := verify(src, tgt, sourcePath, targetPath, verbose)

	if jsonOut {
		data, _ := json.MarshalIndent(rep, "", "  ")
		fmt.Println(string(data))
	} else {
		printText(rep, verbose)
	}
	os.Exit(0)
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

func loadSource(path string) (sourceFP, error) {
	var src sourceFP
	data, err := os.ReadFile(path)
	if err != nil {
		return src, err
	}
	data = stripControlChars(data)
	if err := yaml.Unmarshal(data, &src); err != nil {
		return src, fmt.Errorf("parse yaml: %w", err)
	}
	return src, nil
}

// stripControlChars removes ASCII control bytes that some CyberHub-exported
// YAML files carry at EOF (e.g. trailing 0x08 backspace), which the yaml
// parser rejects. Preserves \t, \n, \r.
func stripControlChars(in []byte) []byte {
	out := in[:0:len(in)]
	for _, b := range in {
		if b < 0x20 && b != '\t' && b != '\n' && b != '\r' {
			continue
		}
		out = append(out, b)
	}
	return out
}

func loadTarget(path string) (fingers.Fingers, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// Try array form first (fingers canonical).
	var arr fingers.Fingers
	if err := yaml.Unmarshal(data, &arr); err == nil && len(arr) > 0 && arr[0] != nil && arr[0].Name != "" {
		if err := compileFingers(arr); err != nil {
			return nil, err
		}
		return arr, nil
	}
	// Fall back to single-finger form.
	var single fingers.Finger
	if err := yaml.Unmarshal(data, &single); err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}
	if single.Name == "" {
		return nil, fmt.Errorf("target yaml has no fingers (missing 'name' or malformed)")
	}
	fs := fingers.Fingers{&single}
	if err := compileFingers(fs); err != nil {
		return nil, err
	}
	return fs, nil
}

func compileFingers(fs fingers.Fingers) error {
	for _, f := range fs {
		if err := f.Compile(false); err != nil {
			return fmt.Errorf("compile finger %s: %w", f.Name, err)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

func verify(src sourceFP, tgt fingers.Fingers, srcPath, tgtPath string, verbose bool) report {
	rep := report{
		SourcePath:    srcPath,
		TargetPath:    tgtPath,
		SourceName:    src.Name,
		TopExpression: src.Expression,
		TargetCount:   len(tgt),
		Consistent:    true,
	}
	for _, f := range tgt {
		rep.TargetFingers = append(rep.TargetFingers, f.Name)
	}

	// Detect cross-path composition which fingers cannot model: if top expression
	// contains '&&' and referenced rules have different request.path, warn.
	if paths := collectRequestPaths(src); len(paths) > 1 && strings.Contains(src.Expression, "&&") {
		rep.Warnings = append(rep.Warnings,
			fmt.Sprintf("source has '&&' across rules with different request paths %v — "+
				"fingers cannot faithfully represent per-path AND; verification assumes single-response semantics",
				paths))
	}

	mocks := generateMocks(src, tgt)

	// Report per target finger, but evaluate together (fingers engine OR-across-fingers).
	// For simplicity and symmetry with pocverify, report under one synthetic block
	// named after the source top expression. Individual finger hits are still recorded.
	block := fingerResult{Name: src.Name, Consistent: true}
	for _, m := range mocks {
		cr := evaluateCase(src, tgt, m)
		if verbose {
			mCopy := m
			cr.Mock = &mCopy
		}
		rep.TotalCases++
		if cr.Consistent {
			rep.Passed++
		} else {
			rep.Failed++
			block.Consistent = false
			rep.Consistent = false
		}
		block.Cases = append(block.Cases, cr)
	}
	rep.Results = append(rep.Results, block)
	return rep
}

func collectRequestPaths(src sourceFP) []string {
	seen := map[string]bool{}
	for _, r := range src.Rules {
		if r.Request != nil && r.Request.Path != "" {
			seen[r.Request.Path] = true
		}
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

func evaluateCase(src sourceFP, tgt fingers.Fingers, m mockResponse) caseResult {
	cr := caseResult{MockName: m.Name}
	srcOK, srcErr := evalSource(src, m)
	tgtOK, tgtHit, tgtErr := evalTarget(tgt, m)
	cr.SourceResult = srcOK
	cr.TargetResult = tgtOK
	cr.TargetHit = tgtHit
	if srcErr != nil {
		cr.SourceError = srcErr.Error()
	}
	if tgtErr != nil {
		cr.TargetError = tgtErr.Error()
	}
	cr.Consistent = (srcOK == tgtOK) && cr.SourceError == "" && cr.TargetError == ""
	return cr
}

// ---------------------------------------------------------------------------
// Source evaluation: each rN() is registered as a govaluate function that
// evaluates its DSL expression against the mock.
// ---------------------------------------------------------------------------

func evalSource(src sourceFP, m mockResponse) (bool, error) {
	if strings.TrimSpace(src.Expression) == "" {
		// Some fingerprints omit the top-level expression when there's one rule.
		// Default to OR of all rules.
		if len(src.Rules) == 0 {
			return false, fmt.Errorf("source has no rules")
		}
		for _, r := range src.Rules {
			ok, err := evalXrayDSL(r.Expression, m)
			if err != nil {
				return false, err
			}
			if ok {
				return true, nil
			}
		}
		return false, nil
	}

	funcs := helperFunctions()
	// Register each rule as a no-arg function.
	for name, rule := range src.Rules {
		nameCapture := name
		ruleCapture := rule
		funcs[nameCapture] = func(args ...interface{}) (interface{}, error) {
			ok, err := evalXrayDSL(ruleCapture.Expression, m)
			if err != nil {
				return false, err
			}
			return ok, nil
		}
	}

	e, err := govaluate.NewEvaluableExpressionWithFunctions(src.Expression, funcs)
	if err != nil {
		return false, fmt.Errorf("compile top expression: %w", err)
	}
	res, err := e.Evaluate(nil)
	if err != nil {
		return false, fmt.Errorf("evaluate top expression: %w", err)
	}
	b, ok := res.(bool)
	if !ok {
		return false, fmt.Errorf("top expression did not return bool (got %T)", res)
	}
	return b, nil
}

// evalXrayDSL evaluates a single xray DSL expression (the body of one rule)
// against a mock response. Reused logic from pocverify.
func evalXrayDSL(expr string, m mockResponse) (bool, error) {
	if strings.TrimSpace(expr) == "" {
		return true, nil
	}
	norm := normalizeXrayExpr(expr)
	e, err := govaluate.NewEvaluableExpressionWithFunctions(norm, helperFunctions())
	if err != nil {
		return false, fmt.Errorf("compile xray expr: %w (normalized: %s)", err, norm)
	}
	params := buildXrayParams(expr, m)
	res, err := e.Evaluate(params)
	if err != nil {
		return false, fmt.Errorf("evaluate xray expr: %w", err)
	}
	b, ok := res.(bool)
	if !ok {
		return false, fmt.Errorf("xray expr did not return bool (got %T)", res)
	}
	return b, nil
}

// ---------------------------------------------------------------------------
// xray DSL normalization (lifted from pocverify, adapted for fingerprints)
// ---------------------------------------------------------------------------

var (
	reBytesLiteral = regexp.MustCompile(`b"([^"\\]*(?:\\.[^"\\]*)*)"`)
	// response.headers["X"] or response.headers['X'] (single or double quotes)
	reHeaderRef = regexp.MustCompile(`response\.headers\[["']([^"']+)["']\]`)
	// method-style call on flat ident
	reMethodCall = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*)\.(contains|icontains|bcontains|matches|startsWith|endsWith|submatch|bsubmatch)\(`)
	// method-style call on quoted string literal, xray-specific syntax:
	//   "pattern".matches(target)  →  regex(pattern, target)
	//   "pattern".submatch(target) →  regex(pattern, target)   (best-effort)
	reStringMethodCall = regexp.MustCompile(`"((?:[^"\\]|\\.)*)"\.(matches|submatch|bsubmatch)\(([^)]*)\)`)
	// Match string literals like 'abc' (single-quoted) — convert to double-quoted for govaluate
	reSingleQuoteStr = regexp.MustCompile(`'([^'\\]*(?:\\.[^'\\]*)*)'`)
)

func normalizeXrayExpr(expr string) string {
	out := expr

	// b"..." -> "..."
	out = reBytesLiteral.ReplaceAllString(out, `"$1"`)

	// headers["X"] / headers['X'] -> xray_hdr_x
	out = reHeaderRef.ReplaceAllStringFunc(out, func(match string) string {
		m := reHeaderRef.FindStringSubmatch(match)
		return headerVarName(m[1])
	})

	// response.body_string -> response.body
	out = strings.ReplaceAll(out, "response.body_string", "response.body")
	// response.raw_header -> xray_all_headers (fingers uses full raw content anyway)
	out = strings.ReplaceAll(out, "response.raw_header", "xray_all_headers")

	// dotted idents -> flat vars
	out = strings.ReplaceAll(out, "response.content_type", "xray_content_type")
	out = strings.ReplaceAll(out, "response.status", "xray_status")
	out = strings.ReplaceAll(out, "response.body", "xray_body")

	// 'str' -> "str" for govaluate, but ONLY for single-quoted strings at the
	// top level — inner single quotes embedded inside a double-quoted string
	// (e.g. contains("href='/custom/'")) must stay intact, otherwise the outer
	// string literal would be broken.
	out = convertTopLevelSingleQuotes(out)

	// "pattern".matches(target) -> regex("pattern", target)
	// Must run after single-quote conversion above so xray's 'pat'.matches(x) is
	// normalized first. Parenthesis-balance is simplistic: we only match a
	// single-level argument list here, which covers every xray corpus we've seen.
	out = reStringMethodCall.ReplaceAllStringFunc(out, func(match string) string {
		m := reStringMethodCall.FindStringSubmatch(match)
		pattern, args := m[1], m[3]
		return fmt.Sprintf(`regex("%s", %s)`, pattern, strings.TrimSpace(args))
	})

	// Method calls on idents -> function calls.
	out = reMethodCall.ReplaceAllStringFunc(out, func(match string) string {
		parts := reMethodCall.FindStringSubmatch(match)
		ident, method := parts[1], parts[2]
		fn := mapXrayMethod(method)
		if fn == "regex" {
			return fmt.Sprintf("regex(@@PATTERN@@__%s__", ident)
		}
		return fmt.Sprintf("%s(%s, ", fn, ident)
	})
	out = fixRegexSwap(out)

	return out
}

func mapXrayMethod(m string) string {
	switch m {
	case "contains", "bcontains":
		return "contains"
	case "icontains":
		return "icontains"
	case "matches":
		return "regex"
	case "startsWith":
		return "starts_with"
	case "endsWith":
		return "ends_with"
	case "submatch", "bsubmatch":
		// submatch returns a group dict in xray; for equivalence purposes we treat
		// it like a regex-match boolean. This is best-effort and conservatively
		// indicates a match, not the extracted value.
		return "regex"
	}
	return m
}

func fixRegexSwap(s string) string {
	const marker = "regex(@@PATTERN@@__"
	for {
		i := strings.Index(s, marker)
		if i < 0 {
			return s
		}
		identStart := i + len(marker)
		identEnd := strings.Index(s[identStart:], "__")
		if identEnd < 0 {
			return s
		}
		ident := s[identStart : identStart+identEnd]
		openIdx := i + len("regex(") - 1
		close := matchingParen(s, openIdx)
		if close < 0 {
			return s
		}
		argStart := identStart + identEnd + 2
		args := s[argStart:close]
		rebuilt := fmt.Sprintf("regex(%s, %s)", args, ident)
		s = s[:i] + rebuilt + s[close+1:]
	}
}

func matchingParen(s string, open int) int {
	depth := 0
	for i := open; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// convertTopLevelSingleQuotes replaces single-quoted string literals with
// double-quoted ones, skipping any characters that fall within an existing
// double-quoted literal. Backslash escapes are honored inside both kinds of
// strings so that constructs like "a\"b" and 'a\'b' round-trip correctly.
// Additionally, any UNESCAPED single quote encountered inside a double-quoted
// literal is escaped — govaluate's tokenizer otherwise splits `"x'y'z"` into
// three tokens, which is surprising but well-documented behavior.
func convertTopLevelSingleQuotes(s string) string {
	var out strings.Builder
	i := 0
	for i < len(s) {
		c := s[i]
		if c == '"' {
			// Emit the whole double-quoted literal, escaping any inner '.
			out.WriteByte(c)
			i++
			for i < len(s) {
				c = s[i]
				if c == '\\' && i+1 < len(s) {
					out.WriteByte(c)
					out.WriteByte(s[i+1])
					i += 2
					continue
				}
				if c == '\'' {
					out.WriteString(`\'`)
					i++
					continue
				}
				out.WriteByte(c)
				i++
				if c == '"' {
					break
				}
			}
			continue
		}
		if c == '\'' {
			// Replace this single-quoted literal with a double-quoted one,
			// escaping any embedded double quotes.
			out.WriteByte('"')
			i++
			for i < len(s) {
				c = s[i]
				if c == '\\' && i+1 < len(s) {
					out.WriteByte(c)
					out.WriteByte(s[i+1])
					i += 2
					continue
				}
				if c == '\'' {
					out.WriteByte('"')
					i++
					break
				}
				if c == '"' {
					// Embedded unescaped double quote inside a single-quoted
					// string — escape it so the resulting double-quoted literal
					// remains valid.
					out.WriteString(`\"`)
					i++
					continue
				}
				out.WriteByte(c)
				i++
			}
			continue
		}
		out.WriteByte(c)
		i++
	}
	return out.String()
}

func headerVarName(name string) string {
	n := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(name), "-", "_"))
	return "xray_hdr_" + n
}

func buildXrayParams(origExpr string, m mockResponse) map[string]interface{} {
	p := map[string]interface{}{
		"xray_status":       float64(m.StatusCode),
		"xray_body":         m.Body,
		"xray_content_type": m.Headers["Content-Type"],
	}
	// Seed defaults for every header ident referenced in the expression so that
	// absent headers evaluate to empty string (not "No parameter ...").
	for _, hm := range reHeaderRef.FindAllStringSubmatch(origExpr, -1) {
		p[headerVarName(hm[1])] = ""
	}
	for k, v := range m.Headers {
		p[headerVarName(k)] = v
	}
	// Build raw_header text (used by rare raw_header.bcontains patterns).
	var raw strings.Builder
	keys := make([]string, 0, len(m.Headers))
	for k := range m.Headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&raw, "%s: %s\r\n", k, m.Headers[k])
	}
	p["xray_all_headers"] = raw.String()
	return p
}

// ---------------------------------------------------------------------------
// Target evaluation (fingers production path)
// ---------------------------------------------------------------------------

func evalTarget(fs fingers.Fingers, m mockResponse) (bool, string, error) {
	raw := m.buildRawContent()
	content := fingers.NewContent(raw, "", true)
	for _, f := range fs {
		frame, _, ok := f.PassiveMatch(content)
		if ok {
			name := f.Name
			if frame != nil && frame.Name != "" {
				name = frame.Name
			}
			return true, name, nil
		}
	}
	return false, "", nil
}

// ---------------------------------------------------------------------------
// Mock generation
// ---------------------------------------------------------------------------

func generateMocks(src sourceFP, tgt fingers.Fingers) []mockResponse {
	hdrNeedles := extractSourceHeaderConstraints(src)
	bodyNeedles := extractSourceBodyConstraints(src)
	regexNeedles := extractSourceRegexHints(src)

	// Gather fingers-side needles too so positive mock satisfies both sides.
	tgtBody, tgtHeader, tgtRegex := extractTargetNeedles(tgt)

	// Synthesize positive headers from source + target header constraints.
	headers := buildPositiveHeaders(hdrNeedles, tgtHeader)
	// Body combines all needles.
	bodyParts := append([]string{}, bodyNeedles...)
	bodyParts = append(bodyParts, regexNeedles...)
	bodyParts = append(bodyParts, tgtBody...)
	bodyParts = append(bodyParts, tgtRegex...)
	body := strings.Join(dedup(bodyParts), " ")

	positive := mockResponse{
		Name:       "positive",
		StatusCode: 200,
		Headers:    headers,
		Body:       body,
	}

	wrongStatus := positive
	wrongStatus.Name = "wrong_status"
	wrongStatus.Headers = cloneMap(headers)
	wrongStatus.StatusCode = 500

	emptyBody := positive
	emptyBody.Name = "empty_body"
	emptyBody.Headers = cloneMap(headers)
	emptyBody.Body = ""

	missingHeaders := positive
	missingHeaders.Name = "missing_headers"
	missingHeaders.Headers = map[string]string{}

	mocks := []mockResponse{positive, wrongStatus, emptyBody, missingHeaders}

	// --- drop-source body: positive minus one source body needle ------------
	// Catches "target doesn't check this source needle" (source=F, target=T).
	for i, needle := range bodyNeedles {
		partial := positive
		partial.Name = fmt.Sprintf("drop_body[%d]=%s", i, shortLabel(needle))
		partial.Headers = cloneMap(headers)
		stripped := strings.ReplaceAll(body, needle, "")
		stripped = strings.ReplaceAll(stripped, strings.ToLower(needle), "")
		partial.Body = stripped
		mocks = append(mocks, partial)
	}
	// --- drop-source header: positive minus one source header needle --------
	hdrIdx := 0
	for name, needles := range hdrNeedles {
		for _, needle := range needles {
			partial := positive
			partial.Name = fmt.Sprintf("drop_hdr[%d]=%s/%s", hdrIdx, name, shortLabel(needle))
			hdrIdx++
			reduced := cloneStringSliceMap(hdrNeedles)
			reduced[name] = dropFirst(reduced[name], needle)
			partial.Headers = buildPositiveHeaders(reduced, tgtHeader)
			needleLower := strings.ToLower(needle)
			for k, v := range partial.Headers {
				v = strings.ReplaceAll(v, needle, "")
				v = strings.ReplaceAll(v, needleLower, "")
				partial.Headers[k] = v
			}
			mocks = append(mocks, partial)
		}
	}

	// --- drop-target body: positive minus one target-only body needle -------
	// Catches "target checks a constraint the source doesn't require"
	// (source=T, target=F). Skip needles that also appear in source.
	srcBodySet := toSet(bodyNeedles)
	srcRegexSet := toSet(regexNeedles)
	for i, needle := range tgtBody {
		if srcBodySet[needle] || srcRegexSet[needle] {
			continue
		}
		partial := positive
		partial.Name = fmt.Sprintf("drop_tgt_body[%d]=%s", i, shortLabel(needle))
		partial.Headers = cloneMap(headers)
		stripped := strings.ReplaceAll(body, needle, "")
		stripped = strings.ReplaceAll(stripped, strings.ToLower(needle), "")
		partial.Body = stripped
		mocks = append(mocks, partial)
	}
	// --- drop-target header: for each target-only header keyword -----------
	srcHdrSet := map[string]bool{}
	for _, ns := range hdrNeedles {
		for _, n := range ns {
			srcHdrSet[strings.ToLower(n)] = true
		}
	}
	for i, needle := range tgtHeader {
		if srcHdrSet[strings.ToLower(needle)] {
			continue
		}
		partial := positive
		partial.Name = fmt.Sprintf("drop_tgt_hdr[%d]=%s", i, shortLabel(needle))
		// Rebuild positive headers without injecting THIS target needle via X-Mock.
		reducedTgt := dropFirstLower(tgtHeader, needle)
		partial.Headers = buildPositiveHeaders(hdrNeedles, reducedTgt)
		needleLower := strings.ToLower(needle)
		for k, v := range partial.Headers {
			v = strings.ReplaceAll(v, needle, "")
			v = strings.ReplaceAll(v, needleLower, "")
			partial.Headers[k] = v
		}
		mocks = append(mocks, partial)
	}

	// --- solo-source: mock contains ONLY one source needle -----------------
	// Catches "target treats a single needle as sufficient but source requires
	// it in conjunction with others (AND-composition)". Critical for detecting
	// cross-path `&&` leaks that the single-response model would otherwise hide.
	for i, needle := range bodyNeedles {
		partial := positive
		partial.Name = fmt.Sprintf("solo_body[%d]=%s", i, shortLabel(needle))
		partial.Headers = map[string]string{}
		partial.Body = needle
		mocks = append(mocks, partial)
	}
	soloIdx := 0
	for name, needles := range hdrNeedles {
		for _, needle := range needles {
			partial := positive
			partial.Name = fmt.Sprintf("solo_hdr[%d]=%s/%s", soloIdx, name, shortLabel(needle))
			soloIdx++
			partial.Headers = map[string]string{name: synthesizeHeaderValue(name, []string{needle})}
			partial.Body = ""
			mocks = append(mocks, partial)
		}
	}

	return mocks
}

// dropFirstLower returns a copy of xs with the first occurrence of v (compared
// case-insensitively) removed. Used when pruning target header keywords where
// fingers normalizes case during Compile.
func dropFirstLower(xs []string, v string) []string {
	out := make([]string, 0, len(xs))
	dropped := false
	vl := strings.ToLower(v)
	for _, x := range xs {
		if !dropped && strings.ToLower(x) == vl {
			dropped = true
			continue
		}
		out = append(out, x)
	}
	return out
}

func toSet(xs []string) map[string]bool {
	m := map[string]bool{}
	for _, x := range xs {
		m[x] = true
	}
	return m
}

// extractSourceHeaderConstraints walks all rule expressions and collects every
// response.headers["X"].contains("Y") needle, plus response.content_type patterns.
// Double- and single-quoted arguments are handled separately so internal quotes
// of the OTHER type survive (same reason as extractSourceBodyConstraints).
func extractSourceHeaderConstraints(src sourceFP) map[string][]string {
	out := map[string][]string{}
	reHdrDbl := regexp.MustCompile(`response\.headers\[["']([^"']+)["']\]\.[b]?(?:icontains|contains|bcontains|matches|submatch|bsubmatch)\(b?"((?:[^"\\]|\\.)*)"\)`)
	reHdrSgl := regexp.MustCompile(`response\.headers\[["']([^"']+)["']\]\.[b]?(?:icontains|contains|bcontains|matches|submatch|bsubmatch)\(b?'((?:[^'\\]|\\.)*)'\)`)
	reCTDbl := regexp.MustCompile(`response\.content_type\.[b]?(?:contains|icontains|bcontains)\(b?"((?:[^"\\]|\\.)*)"\)`)
	reCTSgl := regexp.MustCompile(`response\.content_type\.[b]?(?:contains|icontains|bcontains)\(b?'((?:[^'\\]|\\.)*)'\)`)
	for _, r := range src.Rules {
		for _, m := range reHdrDbl.FindAllStringSubmatch(r.Expression, -1) {
			out[m[1]] = append(out[m[1]], m[2])
		}
		for _, m := range reHdrSgl.FindAllStringSubmatch(r.Expression, -1) {
			out[m[1]] = append(out[m[1]], m[2])
		}
		for _, m := range reCTDbl.FindAllStringSubmatch(r.Expression, -1) {
			out["Content-Type"] = append(out["Content-Type"], m[1])
		}
		for _, m := range reCTSgl.FindAllStringSubmatch(r.Expression, -1) {
			out["Content-Type"] = append(out["Content-Type"], m[1])
		}
	}
	return out
}

func extractSourceBodyConstraints(src sourceFP) []string {
	// Separate patterns for double- vs single-quoted arguments so that internal
	// quotes of the OTHER type (e.g. "href='/custom/'") are preserved — using a
	// single greedy negated class would drop needles like
	//   response.body_string.contains("window.location.href='/custom/'").
	reBDbl := regexp.MustCompile(`response\.body(?:_string)?\.[b]?(?:icontains|contains|bcontains)\(b?"((?:[^"\\]|\\.)*)"\)`)
	reBSgl := regexp.MustCompile(`response\.body(?:_string)?\.[b]?(?:icontains|contains|bcontains)\(b?'((?:[^'\\]|\\.)*)'\)`)
	var out []string
	for _, r := range src.Rules {
		for _, m := range reBDbl.FindAllStringSubmatch(r.Expression, -1) {
			out = append(out, m[1])
		}
		for _, m := range reBSgl.FindAllStringSubmatch(r.Expression, -1) {
			out = append(out, m[1])
		}
	}
	return out
}

// extractSourceRegexHints pulls literal substrings from body-side regex/matches patterns.
func extractSourceRegexHints(src sourceFP) []string {
	reRx := regexp.MustCompile(`["']([^"']+)["']\.matches\(response\.body(?:_string)?\)`)
	reRx2 := regexp.MustCompile(`response\.body(?:_string)?\.matches\(["']([^"']+)["']\)`)
	var out []string
	for _, r := range src.Rules {
		for _, m := range reRx.FindAllStringSubmatch(r.Expression, -1) {
			out = append(out, regexLiteralHint(m[1]))
		}
		for _, m := range reRx2.FindAllStringSubmatch(r.Expression, -1) {
			out = append(out, regexLiteralHint(m[1]))
		}
	}
	return out
}

// extractTargetNeedles collects body/header/regexp literal hints from fingers rules.
func extractTargetNeedles(fs fingers.Fingers) (body, header, regex []string) {
	for _, f := range fs {
		for _, r := range f.Rules {
			if r.Regexps == nil {
				continue
			}
			body = append(body, r.Regexps.Body...)
			header = append(header, r.Regexps.Header...)
			for _, pat := range r.Regexps.Regexp {
				regex = append(regex, regexLiteralHint(pat))
			}
		}
	}
	return
}

// buildPositiveHeaders synthesizes a headers map satisfying source header
// constraints and fingers header-keyword patterns.
func buildPositiveHeaders(srcConstraints map[string][]string, tgtHeaderWords []string) map[string]string {
	hdr := map[string]string{}
	for name, needles := range srcConstraints {
		hdr[name] = synthesizeHeaderValue(name, needles)
	}
	// For each fingers target header keyword (e.g. "Server: nginx"), ensure it
	// appears somewhere. fingers does a case-insensitive-lowered substring
	// compare against the full header block, so stuffing into X-Mock works.
	for _, w := range tgtHeaderWords {
		lw := strings.ToLower(w)
		if headerBlockContains(hdr, lw) {
			continue
		}
		// Preserve the full word (including any "Key: val" form) in X-Mock.
		hdr["X-Mock"] = strings.TrimSpace(hdr["X-Mock"] + " " + w)
	}
	return hdr
}

func headerBlockContains(hdr map[string]string, needleLower string) bool {
	for k, v := range hdr {
		if strings.Contains(strings.ToLower(k+": "+v), needleLower) {
			return true
		}
	}
	return false
}

func synthesizeHeaderValue(name string, needles []string) string {
	joined := strings.Join(needles, " ")
	switch strings.ToLower(name) {
	case "set-cookie":
		return joined + "=abc123; Path=/"
	case "location":
		return "/path/" + joined + "/redir"
	case "server":
		return joined
	case "content-type":
		if len(needles) > 0 {
			return needles[0]
		}
		return "text/html"
	}
	return "prefix-" + joined + "-suffix"
}

// regexLiteralHint extracts the longest run of plain chars from a pattern.
func regexLiteralHint(pat string) string {
	stripped := pat
	for _, r := range []string{"^", "$", "(?i)", "(?s)", "(?m)", "\\b", "\\B"} {
		stripped = strings.ReplaceAll(stripped, r, "")
	}
	var best, cur strings.Builder
	flush := func() {
		if cur.Len() > best.Len() {
			best.Reset()
			best.WriteString(cur.String())
		}
		cur.Reset()
	}
	for _, ch := range stripped {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') || ch == '_' || ch == ' ' || ch == '-' || ch == '.' ||
			ch >= 0x4e00 && ch <= 0x9fff {
			cur.WriteRune(ch)
		} else {
			flush()
		}
	}
	flush()
	return strings.TrimSpace(best.String())
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

func printText(r report, verbose bool) {
	fmt.Printf("fingerverify: source=%s target=%s\n", r.SourcePath, r.TargetPath)
	fmt.Printf("  source name: %s\n", r.SourceName)
	fmt.Printf("  top expression: %s\n", r.TopExpression)
	fmt.Printf("  target fingers: %d %v\n", r.TargetCount, r.TargetFingers)

	for _, w := range r.Warnings {
		fmt.Printf("  ! %s\n", w)
	}

	for _, rr := range r.Results {
		fmt.Printf("\nFinger %s\n", rr.Name)
		for _, c := range rr.Cases {
			tag := "PASS"
			if !c.Consistent {
				tag = "FAIL"
			}
			fmt.Printf("    [%s] %-32s source=%s target=%s",
				tag, c.MockName, boolT(c.SourceResult), boolT(c.TargetResult))
			if c.TargetHit != "" {
				fmt.Printf(" hit=%s", c.TargetHit)
			}
			fmt.Println()
			if c.SourceError != "" {
				fmt.Printf("           source error: %s\n", c.SourceError)
			}
			if c.TargetError != "" {
				fmt.Printf("           target error: %s\n", c.TargetError)
			}
			if verbose && c.Mock != nil {
				fmt.Printf("           mock: status=%d headers=%v body=%q\n",
					c.Mock.StatusCode, c.Mock.Headers, truncate(c.Mock.Body, 80))
			}
		}
		fmt.Printf("  finger consistent: %s\n", yesNo(rr.Consistent))
	}

	fmt.Printf("\nSummary: %d/%d consistent, %d divergent\n",
		r.Passed, r.TotalCases, r.Failed)
	overall := "CONSISTENT"
	if !r.Consistent {
		overall = "DIVERGENT"
	}
	fmt.Printf("Overall: %s\n", overall)
}

// ---------------------------------------------------------------------------
// Small utilities
// ---------------------------------------------------------------------------

func cloneMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneStringSliceMap(in map[string][]string) map[string][]string {
	out := make(map[string][]string, len(in))
	for k, v := range in {
		cp := make([]string, len(v))
		copy(cp, v)
		out[k] = cp
	}
	return out
}

func dropFirst(xs []string, v string) []string {
	out := make([]string, 0, len(xs))
	dropped := false
	for _, x := range xs {
		if !dropped && x == v {
			dropped = true
			continue
		}
		out = append(out, x)
	}
	return out
}

func dedup(xs []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		if x == "" || seen[x] {
			continue
		}
		seen[x] = true
		out = append(out, x)
	}
	return out
}

func shortLabel(s string) string {
	r := []rune(s)
	if len(r) > 12 {
		r = append(r[:12], '…')
	}
	out := strings.Map(func(c rune) rune {
		if c == ' ' || c == '\t' || c == '\r' || c == '\n' {
			return '_'
		}
		return c
	}, string(r))
	if out == "" {
		return "x"
	}
	return out
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func boolT(b bool) string {
	if b {
		return "T"
	}
	return "F"
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
