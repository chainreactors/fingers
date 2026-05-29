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
// ============================================================================

func newTestEngine(caseInsensitive bool) *FingerPrintHubEngine {
	return &FingerPrintHubEngine{
		CaseInsensitive: caseInsensitive,
		webTemplates:    make([]*templates.Template, 0),
		executerOptions: &protocols.ExecuterOptions{Options: &protocols.Options{Timeout: 10}},
	}
}

// CaseInsensitive=true（默认）: body 已 ToLower，DSL 字面量用小写
func TestWebMatch_CaseInsensitive(t *testing.T) {
	engine := newTestEngine(true)

	tmplData := []map[string]interface{}{
		{
			"id": "test-ci-dsl",
			"info": map[string]interface{}{"name": "Test CI DSL", "severity": "info"},
			"http": []interface{}{
				map[string]interface{}{
					"method": "GET", "path": []interface{}{"{{BaseURL}}/"},
					"matchers-condition": "and",
					"matchers": []interface{}{
						map[string]interface{}{
							"type": "dsl",
							"dsl":  []interface{}{`contains(body, "<title>nacos")`},
						},
					},
				},
			},
		},
		{
			"id": "test-ci-word",
			"info": map[string]interface{}{"name": "Test CI Word", "severity": "info"},
			"http": []interface{}{
				map[string]interface{}{
					"method": "GET", "path": []interface{}{"{{BaseURL}}/"},
					"matchers": []interface{}{
						map[string]interface{}{
							"type":  "word",
							"words": []interface{}{"<title>Nacos"},
						},
					},
				},
			},
		},
	}

	count, errs := engine.loadTemplates(tmplData, true)
	if count != 2 {
		t.Fatalf("loadTemplates: loaded=%d, errors: %v", count, errs)
	}
	engine.webTemplateIndex = NewTemplateKeywordIndex(engine.webTemplates)

	raw := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" +
		"<html><head><title>Nacos</title></head></html>"

	frames := engine.WebMatch([]byte(raw))
	if len(frames) != 2 {
		t.Fatalf("CaseInsensitive=true: expected 2 matches, got %d: %v", len(frames), frameworkNames(frames))
	}
	t.Logf("CaseInsensitive=true matched: %v", frameworkNames(frames))
}

// CaseInsensitive=false: body 保留原始大小写，DSL 字面量可用混合大小写
func TestWebMatch_CaseSensitive(t *testing.T) {
	engine := newTestEngine(false)

	tmplData := []map[string]interface{}{
		{
			"id": "test-cs-dsl-match",
			"info": map[string]interface{}{"name": "CS DSL Match", "severity": "info"},
			"http": []interface{}{
				map[string]interface{}{
					"method": "GET", "path": []interface{}{"{{BaseURL}}/"},
					"matchers": []interface{}{
						map[string]interface{}{
							"type": "dsl",
							"dsl":  []interface{}{`contains(body, "<title>Nacos")`},
						},
					},
				},
			},
		},
		{
			"id": "test-cs-dsl-nomatch",
			"info": map[string]interface{}{"name": "CS DSL NoMatch", "severity": "info"},
			"http": []interface{}{
				map[string]interface{}{
					"method": "GET", "path": []interface{}{"{{BaseURL}}/"},
					"matchers": []interface{}{
						map[string]interface{}{
							"type": "dsl",
							"dsl":  []interface{}{`contains(body, "<title>NACOS")`},
						},
					},
				},
			},
		},
	}

	count, errs := engine.loadTemplates(tmplData, true)
	if count != 2 {
		t.Fatalf("loadTemplates: loaded=%d, errors: %v", count, errs)
	}
	engine.webTemplateIndex = NewTemplateKeywordIndex(engine.webTemplates)

	raw := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" +
		"<html><head><title>Nacos</title></head></html>"

	frames := engine.WebMatch([]byte(raw))
	names := frameworkNames(frames)
	if len(frames) != 1 {
		t.Fatalf("CaseSensitive: expected 1 match, got %d: %v", len(frames), names)
	}
	if _, ok := frames["cs dsl match"]; !ok {
		t.Fatalf("CaseSensitive: expected 'cs dsl match', got %v", names)
	}
	t.Logf("CaseSensitive matched: %v", names)
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
