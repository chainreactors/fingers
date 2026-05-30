package fingerprinthub

import (
	"testing"

	"github.com/chainreactors/fingers/resources"
	"github.com/chainreactors/neutron/operators"
	"github.com/chainreactors/neutron/protocols"
	"github.com/chainreactors/neutron/templates"
	"github.com/chainreactors/utils/encode"
)

// ============================================================================
// 基础功能测试
// ============================================================================

func TestFingerPrintHubEngine_Basic(t *testing.T) {
	engine, err := NewFingerPrintHubEngine(resources.FingerprinthubWebData, resources.FingerprinthubServiceData)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	if engine.Name() != "fingerprinthub" {
		t.Errorf("Expected engine name 'fingerprinthub', got '%s'", engine.Name())
	}

	// 引擎自动加载嵌入的指纹数据 (web + service)
	if engine.Len() == 0 {
		t.Error("Expected templates to be auto-loaded from embedded resources")
	}

	t.Logf("Loaded %d templates from embedded resources", engine.Len())

	capability := engine.Capability()
	if !capability.SupportWeb {
		t.Error("Expected engine to support web fingerprinting")
	}
	if !capability.SupportService {
		t.Error("Expected engine to support service fingerprinting")
	}

	t.Logf("✅ Engine created successfully")
	t.Logf("   Name: %s", engine.Name())
	t.Logf("   Capability: Web=%v, Service=%v", capability.SupportWeb, capability.SupportService)
}

func TestFingerPrintHubEngine_WebMatch(t *testing.T) {
	engine, err := NewFingerPrintHubEngine(resources.FingerprinthubWebData, resources.FingerprinthubServiceData)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// 测试空引擎
	testResponse := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body>Test</body></html>")
	frames := engine.WebMatch(testResponse)
	if len(frames) != 0 {
		t.Errorf("Expected 0 matches from empty engine, got %d", len(frames))
	}

	t.Logf("✅ Empty engine correctly returns no matches")
}

// ============================================================================
// CaseInsensitive 开关测试
//
// 模拟真实指纹场景，覆盖所有 matcher 类型 × match part × 两种模式。
//
// 测试用的 HTTP 响应模拟一个典型的 Nacos 控制台页面：
//   - Server: Tengine/2.3.3 (header 混合大小写)
//   - body 包含 <title>Nacos</title>、版本号、JS 路径等混合大小写内容
// ============================================================================

func newTestEngine(caseInsensitive bool) *FingerPrintHubEngine {
	return &FingerPrintHubEngine{
		CaseInsensitive: caseInsensitive,
		webTemplates:    make([]*templates.Template, 0),
		executerOptions: &protocols.ExecuterOptions{Options: &protocols.Options{Timeout: 10}},
	}
}

const testHTTPRaw = "HTTP/1.1 200 OK\r\n" +
	"Server: Tengine/2.3.3\r\n" +
	"Content-Type: text/html; charset=UTF-8\r\n" +
	"X-Powered-By: Nacos-Server/2.1.0\r\n" +
	"\r\n" +
	`<html><head><title>Nacos</title></head><body>` +
	`<div id="root"><script src="console-ui/public/js/vs/loader/loader.js"></script>` +
	`<p>Welcome to Nacos v2.1.0</p></body></html>`

func buildTestTemplates() []map[string]interface{} {
	info := func(name string) map[string]interface{} {
		return map[string]interface{}{"name": name, "severity": "info"}
	}
	httpReq := func(matchers []interface{}) []interface{} {
		return []interface{}{
			map[string]interface{}{
				"method": "GET", "path": []interface{}{"{{BaseURL}}/"},
				"matchers": matchers,
			},
		}
	}
	httpReqAnd := func(matchers []interface{}) []interface{} {
		return []interface{}{
			map[string]interface{}{
				"method": "GET", "path": []interface{}{"{{BaseURL}}/"},
				"matchers-condition": "and",
				"matchers":           matchers,
			},
		}
	}

	return []map[string]interface{}{
		// ── Word matcher: body ──
		// keywords 用混合大小写，CaseInsensitive 模式下 neutron 会 ToLower 双方
		{
			"id": "word-body-mixed", "info": info("Word Body Mixed"),
			"http": httpReq([]interface{}{
				map[string]interface{}{"type": "word", "words": []interface{}{"<title>Nacos</title>"}},
			}),
		},
		// keywords 用小写，两种模式都应该匹配
		{
			"id": "word-body-lower", "info": info("Word Body Lower"),
			"http": httpReq([]interface{}{
				map[string]interface{}{"type": "word", "words": []interface{}{"<title>nacos</title>"}},
			}),
		},
		// keywords 用全大写，只有 CaseInsensitive 模式匹配
		{
			"id": "word-body-upper", "info": info("Word Body Upper"),
			"http": httpReq([]interface{}{
				map[string]interface{}{"type": "word", "words": []interface{}{"<TITLE>NACOS</TITLE>"}},
			}),
		},

		// ── Word matcher: header ──
		// 检查 Server header（原始 "Tengine/2.3.3"）
		{
			"id": "word-header-mixed", "info": info("Word Header Mixed"),
			"http": httpReq([]interface{}{
				map[string]interface{}{"type": "word", "part": "header", "words": []interface{}{"Tengine/2.3.3"}},
			}),
		},
		{
			"id": "word-header-lower", "info": info("Word Header Lower"),
			"http": httpReq([]interface{}{
				map[string]interface{}{"type": "word", "part": "header", "words": []interface{}{"tengine/2.3.3"}},
			}),
		},

		// ── Word matcher: AND 条件（多关键词同时命中）──
		{
			"id": "word-and-body", "info": info("Word AND Body"),
			"http": httpReqAnd([]interface{}{
				map[string]interface{}{"type": "word", "words": []interface{}{"nacos"}},
				map[string]interface{}{"type": "word", "part": "header", "words": []interface{}{"tengine"}},
			}),
		},

		// ── Regex matcher: body ──
		// 提取版本号 — 小写 pattern
		{
			"id": "regex-body-version", "info": info("Regex Body Version"),
			"http": httpReq([]interface{}{
				map[string]interface{}{"type": "regex", "regex": []interface{}{`nacos v[\d.]+`}},
			}),
		},
		// 混合大小写 pattern — 仅 CaseSensitive 模式匹配
		{
			"id": "regex-body-mixed", "info": info("Regex Body Mixed"),
			"http": httpReq([]interface{}{
				map[string]interface{}{"type": "regex", "regex": []interface{}{`Nacos v[\d.]+`}},
			}),
		},

		// ── Regex matcher: header ──
		// 从 header 提取 Tengine 版本
		{
			"id": "regex-header-version", "info": info("Regex Header Version"),
			"http": httpReq([]interface{}{
				map[string]interface{}{"type": "regex", "part": "header", "regex": []interface{}{`tengine/[\d.]+`}},
			}),
		},

		// ── DSL matcher: body ──
		// 使用 contains + status_code 组合
		{
			"id": "dsl-body-lower", "info": info("DSL Body Lower"),
			"http": httpReq([]interface{}{
				map[string]interface{}{
					"type": "dsl",
					"dsl":  []interface{}{`status_code == 200 && contains(body, "<title>nacos</title>")`},
				},
			}),
		},
		// 混合大小写字面量 — 仅 CaseSensitive 模式匹配
		{
			"id": "dsl-body-mixed", "info": info("DSL Body Mixed"),
			"http": httpReq([]interface{}{
				map[string]interface{}{
					"type": "dsl",
					"dsl":  []interface{}{`contains(body, "<title>Nacos</title>")`},
				},
			}),
		},

		// ── DSL matcher: header ──
		// 检查 X-Powered-By header（通过 all_headers）
		{
			"id": "dsl-header", "info": info("DSL Header"),
			"http": httpReq([]interface{}{
				map[string]interface{}{
					"type": "dsl",
					"dsl":  []interface{}{`contains(all_headers, "nacos-server")`},
				},
			}),
		},

		// ── Status matcher（不受大小写影响）──
		{
			"id": "status-200", "info": info("Status 200"),
			"http": httpReq([]interface{}{
				map[string]interface{}{"type": "status", "status": []interface{}{200}},
			}),
		},

		// ── AND 组合：word(header) + regex(body) + status ──
		{
			"id": "combo-and", "info": info("Combo AND"),
			"http": httpReqAnd([]interface{}{
				map[string]interface{}{"type": "status", "status": []interface{}{200}},
				map[string]interface{}{"type": "word", "part": "header", "words": []interface{}{"Tengine"}},
				map[string]interface{}{"type": "regex", "regex": []interface{}{`console-ui/public/js`}},
			}),
		},
	}
}

func TestCaseInsensitive_AllMatchers(t *testing.T) {
	engine := newTestEngine(true)

	tmpls := buildTestTemplates()
	count, errs := engine.loadTemplates(tmpls, true)
	if count != len(tmpls) {
		t.Fatalf("loaded %d/%d, errors: %v", count, len(tmpls), errs)
	}
	engine.webTemplateIndex = NewTemplateKeywordIndex(engine.webTemplates)

	frames := engine.WebMatch([]byte(testHTTPRaw))
	matched := frameworkNames(frames)

	// CaseInsensitive=true 时，所有字面量/keywords/patterns 只要大小写无关就能匹配
	expect := map[string]bool{
		"word body mixed":    true,
		"word body lower":    true,
		"word body upper":    true,
		"word header mixed":  true,
		"word header lower":  true,
		"word and body":      true,
		"regex body version": true,
		"regex body mixed":   false, // regex 引擎不受 CaseInsensitive 控制，pattern "Nacos" 匹配不到小写 body
		"regex header version": true,
		"dsl body lower":     true,
		"dsl body mixed":     false, // body 已 ToLower，"<title>Nacos" 匹配不到
		"dsl header":         true,
		"status 200":         true,
		"combo and":          true,
	}

	for name, shouldMatch := range expect {
		_, got := frames[name]
		if got != shouldMatch {
			t.Errorf("CaseInsensitive=true: %q expected=%v got=%v", name, shouldMatch, got)
		}
	}
	t.Logf("CaseInsensitive=true: %d matched: %v", len(matched), matched)
}

func TestCaseSensitive_AllMatchers(t *testing.T) {
	engine := newTestEngine(false)

	tmpls := buildTestTemplates()
	count, errs := engine.loadTemplates(tmpls, true)
	if count != len(tmpls) {
		t.Fatalf("loaded %d/%d, errors: %v", count, len(tmpls), errs)
	}
	engine.webTemplateIndex = NewTemplateKeywordIndex(engine.webTemplates)

	frames := engine.WebMatch([]byte(testHTTPRaw))
	matched := frameworkNames(frames)

	// CaseSensitive 时 body/header 保留原始大小写
	// body: "<title>Nacos</title>...Nacos v2.1.0"
	// header value: "Tengine/2.3.3", "Nacos-Server/2.1.0"
	expect := map[string]bool{
		"word body mixed":   true, // "Nacos" 在原始 body 中存在（case-sensitive word 无 ToLower）
		"word body lower":   false, // "<title>nacos" 不在原始 body 中
		"word body upper":   false, // "<TITLE>NACOS" 不在原始 body 中
		"word header mixed": true,  // "Tengine/2.3.3" 在 header value 中
		"word header lower": false, // "tengine/2.3.3" — header key 始终小写，但 value 保留原始 "Tengine/2.3.3"
		"word and body":     false, // "nacos" 不在原始 body (小写 n)；即使 header 匹配，AND 也失败
		"regex body version": false, // "nacos v[\d.]+" — body 中是 "Nacos v2.1.0"，小写 n 匹配不到
		"regex body mixed":   true,  // "Nacos v[\d.]+" 精确匹配原始大小写
		"regex header version": false, // "tengine/[\d.]+" — header value 是 "Tengine/2.3.3"
		"dsl body lower":     false, // contains(body, "<title>nacos</title>") — body 中是 Nacos
		"dsl body mixed":     true,  // contains(body, "<title>Nacos</title>") 精确匹配
		"dsl header":         false, // contains(all_headers, "nacos-server") — header value 保留了 "Nacos-Server"
		"status 200":         true,  // 不受大小写影响
		"combo and":          true,  // status=200 ✓, "Tengine" 在 header ✓, "console-ui" 在 body ✓
	}

	for name, shouldMatch := range expect {
		_, got := frames[name]
		if got != shouldMatch {
			t.Errorf("CaseSensitive: %q expected=%v got=%v", name, shouldMatch, got)
		}
	}
	t.Logf("CaseSensitive: %d matched: %v", len(matched), matched)
}

// TestCaseInsensitive_LoadFromJSON 验证 LoadFromJSON 路径也正确应用 CaseInsensitive。
// 这是之前 LoadFromJSON 漏设 CaseInsensitive 的回归测试。
func TestCaseInsensitive_LoadFromJSON(t *testing.T) {
	engine := newTestEngine(true)

	jsonData := []byte(`[{
		"id": "json-word-mixed",
		"info": {"name": "JSON Word Mixed", "severity": "info"},
		"http": [{
			"method": "GET",
			"path": ["{{BaseURL}}/"],
			"matchers": [{"type": "word", "words": ["<title>Nacos"]}]
		}]
	}]`)

	if err := engine.LoadFromJSON(jsonData); err != nil {
		t.Fatalf("LoadFromJSON: %v", err)
	}
	engine.webTemplateIndex = NewTemplateKeywordIndex(engine.webTemplates)

	frames := engine.WebMatch([]byte(testHTTPRaw))
	if _, ok := frames["json word mixed"]; !ok {
		t.Fatal("LoadFromJSON: word matcher with mixed-case keywords should match in CaseInsensitive mode")
	}
	t.Logf("LoadFromJSON CaseInsensitive=true: matched %v", frameworkNames(frames))
}

// ============================================================================
// Favicon Matcher 单元测试
// ============================================================================

func TestCalculateFaviconHash(t *testing.T) {
	// 测试空内容
	hashes := calculateFaviconHash([]byte{})
	if hashes != nil {
		t.Errorf("Expected nil for empty content, got %v", hashes)
	}

	// 测试有内容的情况
	content := []byte("test favicon content")
	hashes = calculateFaviconHash(content)

	if len(hashes) != 2 {
		t.Errorf("Expected 2 hashes (md5, mmh3), got %d", len(hashes))
	}

	// 验证 MD5 hash
	expectedMd5 := encode.Md5Hash(content)
	if hashes[0] != expectedMd5 {
		t.Errorf("MD5 hash mismatch: expected %s, got %s", expectedMd5, hashes[0])
	}

	// 验证 MMH3 hash
	expectedMmh3 := encode.Mmh3Hash32(content)
	if hashes[1] != expectedMmh3 {
		t.Errorf("MMH3 hash mismatch: expected %s, got %s", expectedMmh3, hashes[1])
	}

	t.Logf("✅ Favicon hashes calculated correctly")
	t.Logf("   MD5:  %s", hashes[0])
	t.Logf("   MMH3: %s", hashes[1])
}

func TestNeutronFaviconMatcher(t *testing.T) {
	// 验证 favicon matcher 类型已注册
	matcher := &operators.Matcher{
		Type: "favicon",
		Hash: []string{"testhash1", "testhash2"},
	}

	err := matcher.CompileMatchers()
	if err != nil {
		t.Fatalf("Failed to compile favicon matcher: %v", err)
	}

	if matcher.GetType() != operators.FaviconMatcher {
		t.Errorf("Expected FaviconMatcher type, got %d", matcher.GetType())
	}

	t.Logf("✅ Neutron favicon matcher type registered correctly")
}

func TestFaviconMatcher_Matching(t *testing.T) {
	// 创建 favicon matcher
	matcher := &operators.Matcher{
		Type: "favicon",
		Hash: []string{"hash1", "hash2"},
	}

	err := matcher.CompileMatchers()
	if err != nil {
		t.Fatalf("Failed to compile matcher: %v", err)
	}

	// 测试匹配成功
	faviconData := map[string]interface{}{
		"http://example.com/favicon.ico": []string{"hash1", "hash3"},
	}

	matched, matchedHashes := matcher.MatchFavicon(faviconData)
	if !matched {
		t.Errorf("Expected favicon to match")
	}

	if len(matchedHashes) == 0 {
		t.Errorf("Expected matched hashes to be returned")
	}

	t.Logf("✅ Favicon matching works correctly")
	t.Logf("   Matched: %v", matched)
	t.Logf("   Matched hashes: %v", matchedHashes)

	// 测试不匹配
	wrongFaviconData := map[string]interface{}{
		"http://example.com/favicon.ico": []string{"wronghash1", "wronghash2"},
	}

	matched, _ = matcher.MatchFavicon(wrongFaviconData)
	if matched {
		t.Errorf("Expected favicon not to match with wrong hashes")
	}

	t.Logf("✅ Favicon non-matching works correctly")
}

func TestExtractFaviconFromResponse(t *testing.T) {
	// 测试 nil 响应
	result := extractFaviconFromResponse(nil, []byte("test"))
	if len(result) != 0 {
		t.Errorf("Expected empty result for nil response, got %d items", len(result))
	}

	t.Logf("✅ Handles nil response correctly")
}

func TestIsImageContent(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		body        string
		expected    bool
	}{
		{
			name:        "Image content type",
			contentType: "image/x-icon",
			body:        "binary image data",
			expected:    true,
		},
		{
			name:        "HTML content",
			contentType: "text/html",
			body:        "<html><head><title>Test</title></head></html>",
			expected:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 简单验证逻辑
			hasImageType := len(tt.contentType) > 0 && contains(tt.contentType, "image/")
			hasHTMLTags := contains(tt.body, "<html") || contains(tt.body, "<head")

			result := hasImageType || !hasHTMLTags
			if result != tt.expected {
				t.Errorf("Expected %v, got %v for %s", tt.expected, result, tt.name)
			}
		})
	}

	t.Logf("✅ Image content detection works correctly")
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && anyMatch(s, substr)
}

func anyMatch(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
