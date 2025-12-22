package fingerprinthub

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/chainreactors/fingers/common"
	"github.com/chainreactors/fingers/resources"
	"github.com/chainreactors/neutron/protocols"
	http2 "github.com/chainreactors/neutron/protocols/http"
	"github.com/chainreactors/neutron/templates"
	"github.com/chainreactors/utils/encode"
	"github.com/chainreactors/utils/httputils"
	"gopkg.in/yaml.v3"
)

// FingerPrintHubEngine 基于 neutron 的 FingerprintHub 引擎
type FingerPrintHubEngine struct {
	webTemplates     []*templates.Template // Web 指纹模板
	serviceTemplates []*templates.Template // Service 指纹模板
	executerOptions  *protocols.ExecuterOptions
}

// NewFingerPrintHubEngine 创建新的引擎实例
func NewFingerPrintHubEngine(webData, serviceData []byte) (*FingerPrintHubEngine, error) {
	engine := &FingerPrintHubEngine{
		webTemplates:     make([]*templates.Template, 0),
		serviceTemplates: make([]*templates.Template, 0),
		executerOptions: &protocols.ExecuterOptions{
			Options: &protocols.Options{
				Timeout: 10, // 默认 10 秒超时
			},
		},
	}

	// 加载 web 指纹
	var webTemplates []map[string]interface{}
	if err := resources.UnmarshalData(webData, &webTemplates); err != nil {
		return nil, fmt.Errorf("failed to unmarshal web fingerprints: %w", err)
	}

	webCount, webErrors := engine.loadTemplates(webTemplates, true)

	// 加载 service 指纹
	var serviceTemplates []map[string]interface{}
	if err := resources.UnmarshalData(serviceData, &serviceTemplates); err != nil {
		return nil, fmt.Errorf("failed to unmarshal service fingerprints: %w", err)
	}

	serviceCount, serviceErrors := engine.loadTemplates(serviceTemplates, false)

	// 显示前几个错误
	allErrors := append(webErrors, serviceErrors...)
	if len(allErrors) > 0 && len(allErrors) < 10 {
		for _, e := range allErrors {
			fmt.Printf("Warning: %v\n", e)
		}
	}

	fmt.Printf("Loaded %d fingerprint templates (%d web, %d service)\n", webCount+serviceCount, webCount, serviceCount)

	return engine, nil
}

// loadTemplates 加载并编译模板
func (engine *FingerPrintHubEngine) loadTemplates(templateData []map[string]interface{}, isWeb bool) (int, []error) {
	loadedCount := 0
	var errors []error

	for _, rawTemplate := range templateData {
		// 将 map 转为 YAML bytes (neutron 使用 YAML unmarshaler)
		yamlBytes, err := yaml.Marshal(rawTemplate)
		if err != nil {
			errors = append(errors, fmt.Errorf("failed to marshal template: %w", err))
			continue
		}

		// 解析模板
		tmpl := &templates.Template{}
		if err := yaml.Unmarshal(yamlBytes, tmpl); err != nil {
			errors = append(errors, fmt.Errorf("failed to unmarshal template: %w", err))
			continue
		}

		// 编译模板
		if err := tmpl.Compile(engine.executerOptions); err != nil {
			errors = append(errors, fmt.Errorf("failed to compile template %s: %w", tmpl.Id, err))
			continue
		}

		// 修复 FingerprintHub 指纹中缺少 ReadSize 和 Input.Read 字段的问题
		for _, netReq := range tmpl.RequestsNetwork {
			for _, input := range netReq.Inputs {
				if input.Read == 0 {
					input.Read = 1024
				}
			}
			if netReq.ReadSize == 0 {
				netReq.ReadSize = 1024
			}
		}

		// 添加到对应的列表
		if isWeb {
			engine.webTemplates = append(engine.webTemplates, tmpl)
		} else {
			engine.serviceTemplates = append(engine.serviceTemplates, tmpl)
		}
		loadedCount++
	}

	return loadedCount, errors
}

// LoadFromCompressedJSON 从压缩的 JSON 数据加载指纹
func (engine *FingerPrintHubEngine) LoadFromCompressedJSON(data []byte) error {
	// 解压 gzip
	gr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gr.Close()

	// 读取解压后的数据
	jsonData, err := io.ReadAll(gr)
	if err != nil {
		return fmt.Errorf("failed to read gzip data: %w", err)
	}

	// 解析 JSON
	var templateData []map[string]interface{}
	if err := json.Unmarshal(jsonData, &templateData); err != nil {
		return fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	// 转换为 YAML 并加载每个模板
	loadedCount := 0
	var errors []error

	for _, rawTemplate := range templateData {
		// 将 map 转为 YAML bytes (neutron 使用 YAML unmarshaler)
		yamlBytes, err := yaml.Marshal(rawTemplate)
		if err != nil {
			errors = append(errors, fmt.Errorf("failed to marshal template: %w", err))
			continue
		}

		// 解析模板
		tmpl := &templates.Template{}
		err = yaml.Unmarshal(yamlBytes, tmpl)
		if err != nil {
			errors = append(errors, fmt.Errorf("failed to unmarshal template: %w", err))
			continue
		}

		// 编译模板
		err = tmpl.Compile(engine.executerOptions)
		if err != nil {
			errors = append(errors, fmt.Errorf("failed to compile template %s: %w", tmpl.Id, err))
			continue
		}

		// 修复 FingerprintHub 指纹中缺少 ReadSize 和 Input.Read 字段的问题
		for _, netReq := range tmpl.RequestsNetwork {
			for _, input := range netReq.Inputs {
				if input.Read == 0 {
					input.Read = 1024
				}
			}
			if netReq.ReadSize == 0 {
				netReq.ReadSize = 1024
			}
		}

		// 根据模板类型添加到对应的列表
		// web 指纹包含 HTTP 请求，service 指纹包含 network 请求
		if len(tmpl.RequestsHTTP) > 0 {
			engine.webTemplates = append(engine.webTemplates, tmpl)
		} else if len(tmpl.RequestsNetwork) > 0 {
			engine.serviceTemplates = append(engine.serviceTemplates, tmpl)
		}
		loadedCount++
	}

	if len(errors) > 0 && len(errors) < 10 {
		for _, e := range errors {
			fmt.Printf("Warning: %v\n", e)
		}
	}

	return nil
}

// LoadFromFS 从文件系统加载模板（用于开发测试）
func (engine *FingerPrintHubEngine) LoadFromFS(fsys fs.FS, pattern string) error {
	var loadedCount int
	var errors []error

	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		// 只处理 .yaml 和 .yml 文件
		ext := filepath.Ext(path)
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}

		// 检查是否匹配 pattern
		if pattern != "" {
			matched, _ := filepath.Match(pattern, filepath.Base(path))
			if !matched {
				return nil
			}
		}

		// 读取文件内容
		content, err := fs.ReadFile(fsys, path)
		if err != nil {
			errors = append(errors, fmt.Errorf("failed to read %s: %w", path, err))
			return nil // 继续处理其他文件
		}

		// 解析模板
		tmpl := &templates.Template{}
		err = yaml.Unmarshal(content, tmpl)
		if err != nil {
			errors = append(errors, fmt.Errorf("failed to unmarshal %s: %w", path, err))
			return nil
		}

		// 编译模板
		// neutron 会自动处理 tcp/udp 字段作为 network 的别名
		err = tmpl.Compile(engine.executerOptions)
		if err != nil {
			errors = append(errors, fmt.Errorf("failed to compile %s: %w", path, err))
			return nil
		}

		// 修复 FingerprintHub 指纹中缺少 ReadSize 和 Input.Read 字段的问题
		// 这个修复在编译后执行，适用于所有 network 请求（包括从 tcp/udp 转换来的）
		for _, netReq := range tmpl.RequestsNetwork {
			// 修复 input.Read 字段
			for _, input := range netReq.Inputs {
				if input.Read == 0 {
					input.Read = 1024
				}
			}
			// 修复 ReadSize 字段
			if netReq.ReadSize == 0 {
				netReq.ReadSize = 1024
			}
		}

		// 根据模板类型添加到对应的列表
		// web 指纹包含 HTTP 请求，service 指纹包含 network 请求
		if len(tmpl.RequestsHTTP) > 0 {
			engine.webTemplates = append(engine.webTemplates, tmpl)
		} else if len(tmpl.RequestsNetwork) > 0 {
			engine.serviceTemplates = append(engine.serviceTemplates, tmpl)
		}
		loadedCount++

		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to walk filesystem: %w", err)
	}

	if len(errors) > 0 {
		// 记录所有错误
		for _, e := range errors {
			fmt.Printf("Warning: %v\n", e)
		}
	}

	fmt.Printf("Loaded %d fingerprint templates from filesystem\n", loadedCount)
	return nil
}

// Name 返回引擎名称
func (engine *FingerPrintHubEngine) Name() string {
	return "fingerprinthub"
}

// Len 返回指纹数量
func (engine *FingerPrintHubEngine) Len() int {
	return len(engine.webTemplates) + len(engine.serviceTemplates)
}

// Compile 编译所有模板（已在加载时完成）
func (engine *FingerPrintHubEngine) Compile() error {
	return nil
}

// Capability 返回引擎能力
func (engine *FingerPrintHubEngine) Capability() common.EngineCapability {
	return common.EngineCapability{
		SupportWeb:     true, // 支持 HTTP 指纹
		SupportService: true, // 支持 Service 指纹 (通过 neutron network)
	}
}

// WebMatch 实现 Web 指纹匹配
func (engine *FingerPrintHubEngine) WebMatch(content []byte) common.Frameworks {
	resp := httputils.NewResponseWithRaw(content)
	if resp == nil {
		return make(common.Frameworks)
	}

	// 读取 body
	body := bytes.ToLower(httputils.ReadBody(resp))
	bodyStr := string(body)

	// 构建 neutron 格式的 InternalEvent
	// 复用 neutron 的数据结构，避免重复实现
	event := engine.buildInternalEvent(resp, bodyStr, len(content))

	frames := make(common.Frameworks)

	// 遍历所有 web 模板进行匹配
	for _, tmpl := range engine.webTemplates {
		// 跳过没有 HTTP 请求的模板
		requests := tmpl.GetRequests()
		if len(requests) == 0 {
			continue
		}

		// 检查每个请求的 matchers
		for _, req := range requests {
			if req.Matchers == nil || len(req.Matchers) == 0 {
				continue
			}

			// 使用 neutron 的 Match 方法进行匹配
			// 这里复用了 neutron 的完整匹配逻辑
			matched := engine.matchRequest(req, event)
			if matched {
				// 创建 framework
				name := tmpl.Info.Name
				if name == "" {
					name = tmpl.Id
				}
				frame := common.NewFramework(name, common.FrameFromFingerprintHub)

				// 添加元数据
				if tmpl.Info.Metadata != nil {
					if vendor, ok := tmpl.Info.Metadata["vendor"].(string); ok {
						frame.Attributes.Vendor = vendor
					}
					if product, ok := tmpl.Info.Metadata["product"].(string); ok {
						frame.Attributes.Product = product
					}
				}

				frames.Add(frame)
				break // 找到匹配后跳出
			}
		}
	}

	return frames
}

// buildInternalEvent 构建 neutron 的 InternalEvent
// 复用 neutron 的数据结构，包括 all_headers 等字段
func (engine *FingerPrintHubEngine) buildInternalEvent(resp *http.Response, bodyStr string, contentLength int) protocols.InternalEvent {
	event := make(protocols.InternalEvent)

	// 基础字段
	event["body"] = bodyStr
	event["status_code"] = resp.StatusCode
	event["content_length"] = contentLength

	// header 字段：原始 http.Header
	event["header"] = resp.Header

	// all_headers 字段：neutron 使用的拼接格式
	// 复用这个逻辑避免在 matchSingle 中重复拼接
	event["all_headers"] = engine.buildHeaderString(resp.Header)

	// favicon 字段：提取 favicon hash 用于 favicon matcher
	faviconData := extractFaviconFromResponse(resp, []byte(bodyStr))
	if len(faviconData) > 0 {
		event["favicon"] = faviconData
	}

	return event
}

// buildHeaderString 构建 header 字符串
// 复用 neutron 的格式：小写的 "key: value\n" 格式
func (engine *FingerPrintHubEngine) buildHeaderString(header http.Header) string {
	var builder strings.Builder
	for key, values := range header {
		for _, value := range values {
			builder.WriteString(strings.ToLower(key))
			builder.WriteString(": ")
			builder.WriteString(strings.ToLower(value))
			builder.WriteString("\n")
		}
	}
	return builder.String()
}

// matchRequest 检查请求的所有 matchers 是否匹配
// 复用 neutron 的 Request.Match 方法
func (engine *FingerPrintHubEngine) matchRequest(req *http2.Request, event protocols.InternalEvent) bool {
	if req.Matchers == nil || len(req.Matchers) == 0 {
		return false
	}

	// 根据 MatchersCondition 决定逻辑
	matchersCondition := req.MatchersCondition
	if matchersCondition == "" {
		matchersCondition = "or" // 默认为 OR
	}

	matchedCount := 0
	for _, matcher := range req.Matchers {
		// 直接使用 neutron 的 Request.Match 方法
		// 这样可以复用所有的匹配逻辑，包括 getMatchPart 等
		matched, _ := req.Match(event, matcher)
		if matched {
			matchedCount++
			if matchersCondition == "or" {
				return true // OR 条件下，任意匹配即可
			}
		} else {
			if matchersCondition == "and" {
				return false // AND 条件下，任意不匹配即失败
			}
		}
	}

	// AND 条件下，需要所有 matcher 都匹配
	if matchersCondition == "and" {
		return matchedCount == len(req.Matchers)
	}

	return false
}

// ServiceMatch 实现 Service 指纹匹配
func (engine *FingerPrintHubEngine) ServiceMatch(host string, portStr string, level int, sender common.ServiceSender, callback common.ServiceCallback) *common.ServiceResult {
	// 构建目标地址
	target := fmt.Sprintf("%s:%s", host, portStr)

	// 创建扫描上下文
	scanCtx := &protocols.ScanContext{
		Input: target,
	}

	// 遍历所有 service 模板，找到包含 network 请求的模板
	for _, tmpl := range engine.serviceTemplates {
		// 检查是否有 network 请求
		if len(tmpl.RequestsNetwork) == 0 {
			continue
		}

		// 遍历所有 network 请求
		for _, networkReq := range tmpl.RequestsNetwork {
			// 执行 network 请求
			var matched bool
			err := networkReq.ExecuteWithResults(scanCtx, nil, nil, func(event *protocols.InternalWrappedEvent) {
				// 检查是否有匹配结果
				// FingerprintHub service-fingerprint 使用 extractors 而不是 matchers
				// 如果有 extractor 提取到值，说明匹配成功
				if event.OperatorsResult != nil {
					// 有 matchers 的情况
					if event.OperatorsResult.Matched {
						matched = true
					}
					// 有 extractors 的情况 - 提取到值说明匹配成功
					if len(event.OperatorsResult.OutputExtracts) > 0 {
						matched = true
					}
				}

				if matched {
					// 构建 Framework
					name := tmpl.Info.Name
					if name == "" {
						name = tmpl.Id
					}
					frame := common.NewFramework(name, common.FrameFromFingerprintHub)

					// 添加元数据
					if tmpl.Info.Metadata != nil {
						if vendor, ok := tmpl.Info.Metadata["vendor"].(string); ok {
							frame.Attributes.Vendor = vendor
						}
						if product, ok := tmpl.Info.Metadata["product"].(string); ok {
							frame.Attributes.Product = product
						}
					}

					// 创建 ServiceResult 并通过回调返回
					if callback != nil {
						callback(&common.ServiceResult{
							Framework: frame,
						})
					}
				}
			})

			if err != nil {
				// 忽略错误继续尝试其他指纹
				continue
			}

			// 如果匹配成功，可以选择提前返回
			if matched {
				// 这里选择继续匹配其他指纹，以便返回所有可能的匹配
				// 如果只需要第一个匹配，可以在这里 return
			}
		}
	}

	return nil
}

// calculateFaviconHash 计算 favicon 的 MD5 和 MMH3 hash
// 返回 [md5, mmh3] 格式的 hash 数组
func calculateFaviconHash(content []byte) []string {
	if len(content) == 0 {
		return nil
	}

	md5Hash := encode.Md5Hash(content)
	mmh3Hash := encode.Mmh3Hash32(content)

	return []string{md5Hash, mmh3Hash}
}

// extractFaviconFromResponse 从 HTTP 响应中提取 favicon 数据
// 返回 map[url][]hash 格式的数据，用于 favicon matcher
func extractFaviconFromResponse(resp *http.Response, body []byte) map[string]interface{} {
	faviconData := make(map[string]interface{})

	// 检查响应和请求是否有效
	if resp == nil || resp.Request == nil || resp.Request.URL == nil {
		return faviconData
	}

	// 如果响应本身是 favicon.ico
	if strings.HasSuffix(resp.Request.URL.Path, "/favicon.ico") {
		if isImageContent(resp, body) {
			hashes := calculateFaviconHash(body)
			if hashes != nil {
				faviconData[resp.Request.URL.String()] = hashes
			}
		}
	}

	// TODO: 未来可以扩展支持从 HTML 中提取 <link rel="icon"> 标签
	// 目前仅支持直接请求 favicon.ico 的场景

	return faviconData
}

// isImageContent 判断响应内容是否为图片
func isImageContent(resp *http.Response, body []byte) bool {
	// 检查 Content-Type
	contentType := resp.Header.Get("Content-Type")
	if strings.Contains(contentType, "image/") {
		return true
	}

	// 简单检查：如果内容可以解析为 UTF-8 文本且包含 HTML 标签，则不是图片
	if len(body) > 0 {
		bodyStr := string(body)
		htmlTags := []string{"<html", "<head", "<script", "<div", "<title", "<?xml"}
		for _, tag := range htmlTags {
			if strings.Contains(strings.ToLower(bodyStr), tag) {
				return false
			}
		}
	}

	return true
}
