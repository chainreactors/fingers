package main

import (
	"compress/gzip"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	gonmap "github.com/chainreactors/fingers/nmap"
	"gopkg.in/yaml.v3"
)

// DataSource 定义数据源接口
type DataSource interface {
	Name() string                       // 数据源名称
	URL() string                        // 下载URL
	CacheFileName() string              // 本地缓存文件名
	OutputFileName() string             // 输出JSON文件名
	Download(client *http.Client) error // 下载逻辑
	Transform() error                   // 转换逻辑
}

// ProbesDataSource nmap-service-probes数据源
type ProbesDataSource struct{}

func (p *ProbesDataSource) Name() string { return "probes" }
func (p *ProbesDataSource) URL() string {
	return "https://raw.githubusercontent.com/nmap/nmap/master/nmap-service-probes"
}
func (p *ProbesDataSource) CacheFileName() string  { return "nmap-service-probes.txt" }
func (p *ProbesDataSource) OutputFileName() string { return "resources/nmap-service-probes.json.gz" }

func (p *ProbesDataSource) Download(client *http.Client) error {
	return downloadFile(client, p.URL(), p.CacheFileName())
}

func (p *ProbesDataSource) Transform() error {
	return transformProbes(p.CacheFileName(), p.OutputFileName())
}

// ServicesDataSource nmap-services数据源
type ServicesDataSource struct{}

func (s *ServicesDataSource) Name() string { return "services" }
func (s *ServicesDataSource) URL() string {
	return "https://raw.githubusercontent.com/nmap/nmap/master/nmap-services"
}
func (s *ServicesDataSource) CacheFileName() string  { return "nmap-services.txt" }
func (s *ServicesDataSource) OutputFileName() string { return "resources/nmap-services.json.gz" }

func (s *ServicesDataSource) Download(client *http.Client) error {
	return downloadFile(client, s.URL(), s.CacheFileName())
}

func (s *ServicesDataSource) Transform() error {
	return transformServices(s.CacheFileName(), s.OutputFileName())
}

// FingerprintHubWebDataSource fingerprinthub web指纹数据源
type FingerprintHubWebDataSource struct{}

func (f *FingerprintHubWebDataSource) Name() string { return "fingerprinthub-web" }
func (f *FingerprintHubWebDataSource) URL() string {
	return "https://github.com/0x727/FingerprintHub/releases/latest/download/web_fingerprint_v4.json"
}
func (f *FingerprintHubWebDataSource) CacheFileName() string { return "fingerprinthub-web.json" }
func (f *FingerprintHubWebDataSource) OutputFileName() string {
	return "resources/fingerprinthub_web.json.gz"
}

func (f *FingerprintHubWebDataSource) Download(client *http.Client) error {
	// 优先使用本地 refer 目录的文件
	localFile := "refer/FingerprintHub/web_fingerprint_v4.json"
	if fileExists(localFile) {
		fmt.Printf("使用本地文件: %s\n", localFile)
		return copyFile(localFile, f.CacheFileName())
	}
	return downloadFile(client, f.URL(), f.CacheFileName())
}

func (f *FingerprintHubWebDataSource) Transform() error {
	return transformJSON(f.CacheFileName(), f.OutputFileName())
}

// FingerprintHubServiceDataSource fingerprinthub service指纹数据源
type FingerprintHubServiceDataSource struct{}

func (f *FingerprintHubServiceDataSource) Name() string { return "fingerprinthub-service" }
func (f *FingerprintHubServiceDataSource) URL() string {
	return "https://github.com/0x727/FingerprintHub/releases/latest/download/service_fingerprint_v4.json"
}
func (f *FingerprintHubServiceDataSource) CacheFileName() string {
	return "fingerprinthub-service.json"
}
func (f *FingerprintHubServiceDataSource) OutputFileName() string {
	return "resources/fingerprinthub_service.json.gz"
}

func (f *FingerprintHubServiceDataSource) Download(client *http.Client) error {
	// 优先使用本地 refer 目录的文件
	localFile := "refer/FingerprintHub/service_fingerprint_v4.json"
	if fileExists(localFile) {
		fmt.Printf("使用本地文件: %s\n", localFile)
		return copyFile(localFile, f.CacheFileName())
	}
	return downloadFile(client, f.URL(), f.CacheFileName())
}

func (f *FingerprintHubServiceDataSource) Transform() error {
	return transformJSON(f.CacheFileName(), f.OutputFileName())
}

// WappalyzerDataSource wappalyzer数据源
type WappalyzerDataSource struct{}

func (w *WappalyzerDataSource) Name() string { return "wappalyzer" }
func (w *WappalyzerDataSource) URL() string {
	return "https://raw.githubusercontent.com/projectdiscovery/wappalyzergo/main/fingerprints_data.json"
}
func (w *WappalyzerDataSource) CacheFileName() string  { return "wappalyzer.json" }
func (w *WappalyzerDataSource) OutputFileName() string { return "resources/wappalyzer.json.gz" }

func (w *WappalyzerDataSource) Download(client *http.Client) error {
	// 优先使用本地 refer 目录的文件
	localFile := "refer/wappalyzergo/fingerprints_data.json"
	if fileExists(localFile) {
		fmt.Printf("使用本地文件: %s\n", localFile)
		return copyFile(localFile, w.CacheFileName())
	}
	return downloadFile(client, w.URL(), w.CacheFileName())
}

func (w *WappalyzerDataSource) Transform() error {
	return transformJSON(w.CacheFileName(), w.OutputFileName())
}

// EholeDataSource ehole数据源
type EholeDataSource struct{}

func (e *EholeDataSource) Name() string { return "ehole" }
func (e *EholeDataSource) URL() string {
	return "https://raw.githubusercontent.com/EdgeSecurityTeam/EHole/master/finger.json"
}
func (e *EholeDataSource) CacheFileName() string  { return "ehole.json" }
func (e *EholeDataSource) OutputFileName() string { return "resources/ehole.json.gz" }

func (e *EholeDataSource) Download(client *http.Client) error {
	return downloadFile(client, e.URL(), e.CacheFileName())
}

func (e *EholeDataSource) Transform() error {
	return transformJSON(e.CacheFileName(), e.OutputFileName())
}

// GobyDataSource goby数据源
type GobyDataSource struct{}

func (g *GobyDataSource) Name() string { return "goby" }
func (g *GobyDataSource) URL() string {
	return "https://raw.githubusercontent.com/chainreactors/templates/master/goby.json"
}
func (g *GobyDataSource) CacheFileName() string  { return "goby.json" }
func (g *GobyDataSource) OutputFileName() string { return "resources/goby.json.gz" }

func (g *GobyDataSource) Download(client *http.Client) error {
	return downloadFile(client, g.URL(), g.CacheFileName())
}

func (g *GobyDataSource) Transform() error {
	return transformJSON(g.CacheFileName(), g.OutputFileName())
}

// FingersHTTPDataSource fingers HTTP指纹数据源
type FingersHTTPDataSource struct{}

func (f *FingersHTTPDataSource) Name() string { return "fingers-http" }
func (f *FingersHTTPDataSource) URL() string {
	return "https://github.com/chainreactors/templates"
}
func (f *FingersHTTPDataSource) CacheFileName() string  { return "refer/templates" }
func (f *FingersHTTPDataSource) OutputFileName() string { return "resources/fingers_http.json.gz" }

func (f *FingersHTTPDataSource) Download(client *http.Client) error {
	return cloneOrPullRepo(f.URL(), f.CacheFileName())
}

func (f *FingersHTTPDataSource) Transform() error {
	return transformFingersYAML(f.CacheFileName(), "http", f.OutputFileName())
}

// FingersSocketDataSource fingers Socket指纹数据源
type FingersSocketDataSource struct{}

func (f *FingersSocketDataSource) Name() string { return "fingers-socket" }
func (f *FingersSocketDataSource) URL() string {
	return "https://github.com/chainreactors/templates"
}
func (f *FingersSocketDataSource) CacheFileName() string  { return "refer/templates" }
func (f *FingersSocketDataSource) OutputFileName() string { return "resources/fingers_socket.json.gz" }

func (f *FingersSocketDataSource) Download(client *http.Client) error {
	return cloneOrPullRepo(f.URL(), f.CacheFileName())
}

func (f *FingersSocketDataSource) Transform() error {
	return transformFingersYAML(f.CacheFileName(), "socket", f.OutputFileName())
}

// DataManager 数据管理器
type DataManager struct {
	sources map[string]DataSource
	client  *http.Client
}

// NewDataManager 创建数据管理器
func NewDataManager(proxyURL string) *DataManager {
	dm := &DataManager{
		sources: make(map[string]DataSource),
		client:  createHTTPClientWithProxy(proxyURL),
	}

	// 注册数据源
	dm.RegisterSource(&ProbesDataSource{})
	dm.RegisterSource(&ServicesDataSource{})
	dm.RegisterSource(&FingerprintHubWebDataSource{})
	dm.RegisterSource(&FingerprintHubServiceDataSource{})
	dm.RegisterSource(&WappalyzerDataSource{})
	dm.RegisterSource(&EholeDataSource{})
	dm.RegisterSource(&GobyDataSource{})
	dm.RegisterSource(&FingersHTTPDataSource{})
	dm.RegisterSource(&FingersSocketDataSource{})

	return dm
}

// RegisterSource 注册数据源
func (dm *DataManager) RegisterSource(source DataSource) {
	dm.sources[source.Name()] = source
}

// GetSource 获取数据源
func (dm *DataManager) GetSource(name string) (DataSource, bool) {
	source, exists := dm.sources[name]
	return source, exists
}

// ListSources 列出所有数据源
func (dm *DataManager) ListSources() []string {
	var names []string
	for name := range dm.sources {
		names = append(names, name)
	}
	return names
}

// Download 下载数据源
func (dm *DataManager) Download(sourceName string) error {
	source, exists := dm.GetSource(sourceName)
	if !exists {
		return fmt.Errorf("数据源 '%s' 不存在", sourceName)
	}

	fmt.Printf("正在下载 %s 从 %s...\n", source.Name(), source.URL())
	return source.Download(dm.client)
}

// Transform 转换数据源
func (dm *DataManager) Transform(sourceName string) error {
	source, exists := dm.GetSource(sourceName)
	if !exists {
		return fmt.Errorf("数据源 '%s' 不存在", sourceName)
	}

	fmt.Printf("正在转换 %s 数据为 JSON 格式...\n", source.Name())
	return source.Transform()
}

// Update 更新数据源（下载+转换）
func (dm *DataManager) Update(sourceName string) error {
	if err := dm.Download(sourceName); err != nil {
		return err
	}
	return dm.Transform(sourceName)
}

// DownloadAll 下载所有数据源
func (dm *DataManager) DownloadAll() error {
	var errors []string
	successCount := 0

	for name := range dm.sources {
		if err := dm.Download(name); err != nil {
			errMsg := fmt.Sprintf("下载 %s 失败: %v", name, err)
			fmt.Println("⚠ " + errMsg)
			errors = append(errors, errMsg)
		} else {
			successCount++
		}
	}

	fmt.Printf("\n下载完成: 成功 %d 个, 失败 %d 个\n", successCount, len(errors))

	if len(errors) > 0 {
		fmt.Println("\n失败的数据源:")
		for _, err := range errors {
			fmt.Println("  - " + err)
		}
	}

	return nil
}

// TransformAll 转换所有数据源
func (dm *DataManager) TransformAll() error {
	var errors []string
	successCount := 0

	for name := range dm.sources {
		if err := dm.Transform(name); err != nil {
			errMsg := fmt.Sprintf("转换 %s 失败: %v", name, err)
			fmt.Println("⚠ " + errMsg)
			errors = append(errors, errMsg)
		} else {
			successCount++
		}
	}

	fmt.Printf("\n转换完成: 成功 %d 个, 失败 %d 个\n", successCount, len(errors))

	if len(errors) > 0 {
		fmt.Println("\n失败的数据源:")
		for _, err := range errors {
			fmt.Println("  - " + err)
		}
	}

	return nil
}

// UpdateAll 更新所有数据源
func (dm *DataManager) UpdateAll() error {
	if err := dm.DownloadAll(); err != nil {
		return err
	}
	return dm.TransformAll()
}

func main() {
	var proxyURL string
	flag.StringVar(&proxyURL, "proxy", "", "HTTP代理地址 (例如: http://127.0.0.1:1080)")
	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		printUsage()
		return
	}

	dm := NewDataManager(proxyURL)
	command := args[0]

	switch command {
	case "download":
		if len(args) == 1 {
			// 下载所有
			if err := dm.DownloadAll(); err != nil {
				log.Fatal(err)
			}
		} else {
			// 下载指定数据源
			for _, sourceName := range args[1:] {
				if err := dm.Download(sourceName); err != nil {
					log.Fatal(err)
				}
			}
		}

	case "transform":
		if len(args) == 1 {
			// 转换所有
			if err := dm.TransformAll(); err != nil {
				log.Fatal(err)
			}
		} else {
			// 转换指定数据源
			for _, sourceName := range args[1:] {
				if err := dm.Transform(sourceName); err != nil {
					log.Fatal(err)
				}
			}
		}

	case "update":
		if len(args) == 1 {
			// 更新所有
			if err := dm.UpdateAll(); err != nil {
				log.Fatal(err)
			}
		} else {
			// 更新指定数据源
			for _, sourceName := range args[1:] {
				if err := dm.Update(sourceName); err != nil {
					log.Fatal(err)
				}
			}
		}

	case "list":
		fmt.Println("可用的数据源:")
		for _, name := range dm.ListSources() {
			source, _ := dm.GetSource(name)
			fmt.Printf("  %-10s - %s\n", name, source.URL())
		}

	default:
		printUsage()
	}
}

func printUsage() {
	fmt.Println("数据转换工具")
	fmt.Println()
	fmt.Println("用法:")
	fmt.Println("  go run cmd/transform/transform.go [flags] <command> [sources...]")
	fmt.Println()
	fmt.Println("标志:")
	fmt.Println("  -proxy string    HTTP代理地址 (例如: http://127.0.0.1:1080)")
	fmt.Println()
	fmt.Println("命令:")
	fmt.Println("  download [sources...]  下载指定数据源（不指定则下载所有）")
	fmt.Println("  transform [sources...] 转换指定数据源（不指定则转换所有）")
	fmt.Println("  update [sources...]    更新指定数据源（不指定则更新所有）")
	fmt.Println("  list                   列出所有可用数据源")
	fmt.Println()
	fmt.Println("可用数据源: probes, services, fingerprinthub-web, fingerprinthub-service, wappalyzer, ehole, goby, fingers-http, fingers-socket")
	fmt.Println()
	fmt.Println("示例:")
	fmt.Println("  go run cmd/transform/transform.go list")
	fmt.Println("  go run cmd/transform/transform.go -proxy http://127.0.0.1:1080 download probes")
	fmt.Println("  go run cmd/transform/transform.go update services")
	fmt.Println("  go run cmd/transform/transform.go -proxy http://127.0.0.1:1080 update")
	fmt.Println("  go run cmd/transform/transform.go download fingerprinthub-web fingerprinthub-service")
	fmt.Println("  go run cmd/transform/transform.go transform fingers-http fingers-socket")
}

// createHTTPClientWithProxy 创建支持代理的HTTP客户端
func createHTTPClientWithProxy(proxyURL string) *http.Client {
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	// 如果提供了代理URL，使用代理
	if proxyURL != "" {
		parsedProxyURL, err := url.Parse(proxyURL)
		if err != nil {
			fmt.Printf("代理URL解析失败: %v，将使用直连\n", err)
		} else {
			transport := &http.Transport{
				Proxy: http.ProxyURL(parsedProxyURL),
			}
			client.Transport = transport
			fmt.Printf("使用代理: %s\n", proxyURL)
		}
	}

	return client
}

// downloadFile 通用文件下载函数
func downloadFile(client *http.Client, url, filename string) error {
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("下载失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("下载失败，状态码: %d", resp.StatusCode)
	}

	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("创建本地文件失败: %v", err)
	}
	defer file.Close()

	_, err = io.Copy(file, resp.Body)
	if err != nil {
		return fmt.Errorf("保存文件失败: %v", err)
	}

	fmt.Printf("✓ 下载完成: %s\n", filename)
	return nil
}

// writeGzipJSON 写入gzip压缩的JSON文件
func writeGzipJSON(data interface{}, filename string) error {
	// 确保输出目录存在
	if err := os.MkdirAll(filepath.Dir(filename), 0755); err != nil {
		return fmt.Errorf("创建输出目录失败: %v", err)
	}

	// 转换为 JSON
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("JSON 序列化失败: %v", err)
	}

	// 创建gzip压缩文件
	outputFile, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("创建输出文件失败: %v", err)
	}
	defer outputFile.Close()

	// 创建gzip写入器
	gzipWriter := gzip.NewWriter(outputFile)
	defer gzipWriter.Close()

	// 写入压缩数据
	_, err = gzipWriter.Write(jsonData)
	if err != nil {
		return fmt.Errorf("写入压缩数据失败: %v", err)
	}

	fmt.Printf("✓ 转换完成: %s\n", filename)

	// 显示文件大小
	if outputStat, err := os.Stat(filename); err == nil {
		fmt.Printf("  - 文件大小: %d bytes (%.2f KB)\n", outputStat.Size(), float64(outputStat.Size())/1024)
	}

	return nil
}

// fileExists 检查文件是否存在
func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return !os.IsNotExist(err)
}

// copyFile 复制文件
func copyFile(src, dst string) error {
	sourceData, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("读取源文件失败: %v", err)
	}

	err = os.WriteFile(dst, sourceData, 0644)
	if err != nil {
		return fmt.Errorf("写入目标文件失败: %v", err)
	}

	fmt.Printf("✓ 文件复制完成: %s -> %s\n", src, dst)
	return nil
}

// Service 代表一个服务条目
type Service struct {
	Name        string  `json:"name"`
	Port        int     `json:"port"`
	Protocol    string  `json:"protocol"`
	Probability float64 `json:"probability"`
	Comments    string  `json:"comments,omitempty"`
}

// ServicesData 代表解析后的services数据结构
type ServicesData struct {
	Services []Service `json:"services"`
}

// transformServices 转换services数据
func transformServices(cacheFile, outputFile string) error {
	if !fileExists(cacheFile) {
		return fmt.Errorf("找不到文件: %s，请先下载", cacheFile)
	}

	fmt.Printf("使用本地缓存文件: %s\n", cacheFile)
	content, err := os.ReadFile(cacheFile)
	if err != nil {
		return fmt.Errorf("读取本地文件失败: %v", err)
	}

	fmt.Printf("解析服务数据...\n")
	data := parseNmapServices(string(content))

	if err := writeGzipJSON(data, outputFile); err != nil {
		return err
	}

	fmt.Printf("  - 服务数量: %d\n", len(data.Services))
	fmt.Println()
	fmt.Println("转换后的 JSON 文件可以用于:")
	fmt.Println("1. 快速加载服务数据，避免每次解析原始文件")
	fmt.Println("2. 定期自动更新服务库")
	fmt.Println("3. 在嵌入式资源中使用")

	return nil
}

// transformProbes 转换probes数据
func transformProbes(cacheFile, outputFile string) error {
	if !fileExists(cacheFile) {
		return fmt.Errorf("找不到文件: %s，请先下载", cacheFile)
	}

	fmt.Printf("使用本地缓存文件: %s\n", cacheFile)
	content, err := os.ReadFile(cacheFile)
	if err != nil {
		return fmt.Errorf("读取本地文件失败: %v", err)
	}

	fmt.Printf("解析探针数据...\n")
	data := parseAndExportProbes(string(content))

	fmt.Printf("应用自定义匹配规则...\n")
	applyCustomNMAPMatch(data)

	probeCount := len(data.Probes)
	totalMatches := 0
	for _, probe := range data.Probes {
		totalMatches += len(probe.MatchGroup)
	}

	if err := writeGzipJSON(data, outputFile); err != nil {
		return err
	}

	fmt.Printf("  - 探针数量: %d\n", probeCount)
	fmt.Printf("  - 指纹数量: %d\n", totalMatches)
	fmt.Println()
	fmt.Println("转换后的 JSON 文件可以用于:")
	fmt.Println("1. 快速加载探针数据，避免每次解析原始文件")
	fmt.Println("2. 定期自动更新指纹库")
	fmt.Println("3. 在嵌入式资源中使用")

	return nil
}

// parseNmapServices 解析nmap-services内容
func parseNmapServices(content string) *ServicesData {
	lines := strings.Split(content, "\n")
	var services []Service

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// 跳过空行和注释行
		if len(line) == 0 || strings.HasPrefix(line, "#") {
			continue
		}

		// 解析格式: service-name port/protocol probability [comments]
		// 例如: http 80/tcp 0.484143 # World Wide Web HTTP
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		serviceName := parts[0]
		portProtocol := parts[1]

		// 解析端口和协议
		portProtocolParts := strings.Split(portProtocol, "/")
		if len(portProtocolParts) != 2 {
			continue
		}

		port, err := strconv.Atoi(portProtocolParts[0])
		if err != nil {
			continue
		}

		protocol := portProtocolParts[1]

		// 解析概率值
		var probability float64 = 0.0
		if len(parts) >= 3 {
			if prob, err := strconv.ParseFloat(parts[2], 64); err == nil {
				probability = prob
			}
		}

		// 解析注释（如果存在）
		var comments string
		if commentIndex := strings.Index(line, "#"); commentIndex != -1 {
			comments = strings.TrimSpace(line[commentIndex+1:])
		}

		service := Service{
			Name:        serviceName,
			Port:        port,
			Protocol:    protocol,
			Probability: probability,
			Comments:    comments,
		}

		services = append(services, service)
	}

	return &ServicesData{
		Services: services,
	}
}

// parseAndExportProbes 解析探针内容并导出为数据结构
func parseAndExportProbes(content string) *gonmap.NmapProbesData {
	tempNmap := gonmap.NewTempParser(content)

	probes := make([]*gonmap.Probe, 0, len(tempNmap.GetProbes()))
	for _, probe := range tempNmap.GetProbes() {
		probeCopy := *probe
		probes = append(probes, &probeCopy)
	}

	return &gonmap.NmapProbesData{
		Probes:   probes,
		Services: make(map[string]string),
	}
}

// applyCustomNMAPMatch 应用自定义匹配规则
func applyCustomNMAPMatch(data *gonmap.NmapProbesData) {
	probeMap := make(map[string]*gonmap.Probe)
	for _, probe := range data.Probes {
		probeMap[probe.Name] = probe
	}

	addCustomMatch := func(probeName, matchExpr string) {
		if probe, exists := probeMap[probeName]; exists {
			probe.LoadMatch(matchExpr, false)
		}
	}

	// 新增自定义指纹信息
	addCustomMatch("TCP_GetRequest", `echo m|^GET / HTTP/1.0\r\n\r\n$|s`)
	addCustomMatch("TCP_GetRequest", `mongodb m|.*It looks like you are trying to access MongoDB.*|s p/MongoDB/`)
	addCustomMatch("TCP_GetRequest", `http m|^HTTP/1\.[01] \d\d\d (?:[^\r\n]+\r\n)*?Server: ([^\r\n]+)| p/$1/`)
	addCustomMatch("TCP_GetRequest", `http m|^HTTP/1\.[01] \d\d\d|`)
	addCustomMatch("TCP_NULL", `mysql m|.\x00\x00..j\x04Host '.*' is not allowed to connect to this MariaDB server| p/MariaDB/`)
	addCustomMatch("TCP_NULL", `mysql m|.\x00\x00..j\x04Host '.*' is not allowed to connect to this MySQL server| p/MySQL/`)
	addCustomMatch("TCP_NULL", `mysql m|.\x00\x00\x00\x0a(\d+\.\d+\.\d+)\x00.*caching_sha2_password\x00| p/MariaDB/ v/$1/`)
	addCustomMatch("TCP_NULL", `mysql m|.\x00\x00\x00\x0a([\d.-]+)-MariaDB\x00.*mysql_native_password\x00| p/MariaDB/ v/$1/`)
	addCustomMatch("TCP_NULL", `redis m|-DENIED Redis is running in.*| p/Redis/ i/Protected mode/`)
	addCustomMatch("TCP_NULL", `telnet m|^.*Welcome to visit (.*) series router!.*|s p/$1 Router/`)
	addCustomMatch("TCP_NULL", `telnet m|^Username: ??|`)
	addCustomMatch("TCP_NULL", `telnet m|^.*Telnet service is disabled or Your telnet session has expired due to inactivity.*|s i/Disabled/`)
	addCustomMatch("TCP_NULL", `telnet m|^.*Telnet connection from (.*) refused.*|s i/Refused/`)
	addCustomMatch("TCP_NULL", `telnet m|^.*Command line is locked now, please retry later.*\x0d\x0a\x0d\x0a|s i/Locked/`)
	addCustomMatch("TCP_NULL", `telnet m|^.*Warning: Telnet is not a secure protocol, and it is recommended to use Stelnet.*|s`)
	addCustomMatch("TCP_NULL", `telnet m|^telnetd:|s`)
	addCustomMatch("TCP_NULL", `telnet m|^.*Quopin CLI for (.*)\x0d\x0a\x0d\x0a|s p/$1/`)
	addCustomMatch("TCP_NULL", `telnet m|^\x0d\x0aHello, this is FRRouting \(version ([\d.]+)\).*|s p/FRRouting/ v/$1/`)
	addCustomMatch("TCP_NULL", `telnet m|^.*User Access Verification.*Username:|s`)
	addCustomMatch("TCP_NULL", `telnet m|^Connection failed.  Windows CE Telnet Service cannot accept anymore concurrent users.|s o/Windows/`)
	addCustomMatch("TCP_NULL", `telnet m|^\x0d\x0a\x0d\x0aWelcome to the host.\x0d\x0a.*|s o/Windows/`)
	addCustomMatch("TCP_NULL", `telnet m|^.*Welcome Visiting Huawei Home Gateway\x0d\x0aCopyright by Huawei Technologies Co., Ltd.*Login:|s p/Huawei/`)
}

// transformJSON 转换JSON数据（直接压缩）
func transformJSON(cacheFile, outputFile string) error {
	if !fileExists(cacheFile) {
		return fmt.Errorf("找不到文件: %s，请先下载", cacheFile)
	}

	fmt.Printf("使用本地缓存文件: %s\n", cacheFile)
	content, err := os.ReadFile(cacheFile)
	if err != nil {
		return fmt.Errorf("读取本地文件失败: %v", err)
	}

	// 验证JSON格式
	var data interface{}
	if err := json.Unmarshal(content, &data); err != nil {
		return fmt.Errorf("JSON格式验证失败: %v", err)
	}

	// 确保输出目录存在
	if err := os.MkdirAll(filepath.Dir(outputFile), 0755); err != nil {
		return fmt.Errorf("创建输出目录失败: %v", err)
	}

	// 创建gzip压缩文件
	outFile, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("创建输出文件失败: %v", err)
	}
	defer outFile.Close()

	// 创建gzip写入器
	gzipWriter := gzip.NewWriter(outFile)
	defer gzipWriter.Close()

	// 写入压缩数据
	_, err = gzipWriter.Write(content)
	if err != nil {
		return fmt.Errorf("写入压缩数据失败: %v", err)
	}

	fmt.Printf("✓ 转换完成: %s\n", outputFile)

	// 显示文件大小
	if outputStat, err := os.Stat(outputFile); err == nil {
		fmt.Printf("  - 文件大小: %d bytes (%.2f KB)\n", outputStat.Size(), float64(outputStat.Size())/1024)
	}

	return nil
}

// cloneOrPullRepo 克隆或更新Git仓库
func cloneOrPullRepo(repoURL, targetDir string) error {
	// 检查目录是否存在
	if fileExists(targetDir) {
		fmt.Printf("仓库已存在，正在更新: %s\n", targetDir)
		// 使用 exec.Command 并设置工作目录
		cmd := exec.Command("git", "pull")
		cmd.Dir = targetDir
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("更新仓库失败: %v: %s", err, string(output))
		}
		if len(output) > 0 {
			fmt.Printf("%s\n", string(output))
		}
		fmt.Printf("✓ 仓库更新完成: %s\n", targetDir)
	} else {
		fmt.Printf("正在克隆仓库: %s\n", repoURL)
		// 确保父目录存在
		parentDir := filepath.Dir(targetDir)
		if err := os.MkdirAll(parentDir, 0755); err != nil {
			return fmt.Errorf("创建目录失败: %v", err)
		}
		// 执行 git clone --depth 1
		cmd := exec.Command("git", "clone", "--depth", "1", repoURL, targetDir)
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("克隆仓库失败: %v: %s", err, string(output))
		}
		if len(output) > 0 {
			fmt.Printf("%s\n", string(output))
		}
		fmt.Printf("✓ 仓库克隆完成: %s\n", targetDir)
	}
	return nil
}

// executeCommand 执行shell命令
func executeCommand(cmd string) error {
	fmt.Printf("执行命令: %s\n", cmd)
	// 使用 os/exec 执行命令
	var shellCmd *exec.Cmd
	if runtime.GOOS == "windows" {
		shellCmd = exec.Command("cmd", "/C", cmd)
	} else {
		shellCmd = exec.Command("sh", "-c", cmd)
	}

	output, err := shellCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, string(output))
	}

	if len(output) > 0 {
		fmt.Printf("%s\n", string(output))
	}

	return nil
}

// transformFingersYAML 转换Fingers YAML指纹数据
func transformFingersYAML(repoDir, fingerprintType, outputFile string) error {
	if !fileExists(repoDir) {
		return fmt.Errorf("找不到目录: %s，请先下载", repoDir)
	}

	fmt.Printf("正在收集 %s 类型的指纹...\n", fingerprintType)

	var fingerprints []map[string]interface{}

	// 递归遍历目录
	err := filepath.Walk(repoDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// 跳过目录
		if info.IsDir() {
			return nil
		}

		// 只处理 .yaml 和 .yml 文件
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}

		// 读取文件
		content, err := os.ReadFile(path)
		if err != nil {
			fmt.Printf("警告: 读取文件失败 %s: %v\n", path, err)
			return nil
		}

		// 尝试解析为对象
		var dataMap map[string]interface{}
		if err := yaml.Unmarshal(content, &dataMap); err == nil {
			// 根据类型过滤
			if shouldIncludeFingerprint(dataMap, fingerprintType) {
				fingerprints = append(fingerprints, dataMap)
			}
			return nil
		}

		// 尝试解析为数组
		var dataArray []map[string]interface{}
		if err := yaml.Unmarshal(content, &dataArray); err == nil {
			// 遍历数组中的每个元素
			for _, item := range dataArray {
				if shouldIncludeFingerprint(item, fingerprintType) {
					fingerprints = append(fingerprints, item)
				}
			}
			return nil
		}

		// 两种格式都解析失败
		fmt.Printf("警告: 解析YAML失败 %s\n", path)

		return nil
	})

	if err != nil {
		return fmt.Errorf("遍历目录失败: %v", err)
	}

	fmt.Printf("收集到 %d 个 %s 指纹\n", len(fingerprints), fingerprintType)

	// 写入 gzip 压缩的 JSON
	if err := writeGzipJSON(fingerprints, outputFile); err != nil {
		return err
	}

	fmt.Printf("  - 指纹数量: %d\n", len(fingerprints))
	return nil
}

// shouldIncludeFingerprint 判断指纹是否应该包含在指定类型中
func shouldIncludeFingerprint(data map[string]interface{}, fingerprintType string) bool {
	if fingerprintType == "http" {
		// HTTP 指纹包含 http 或 requests 字段
		if _, hasHTTP := data["http"]; hasHTTP {
			return true
		}
		if _, hasRequests := data["requests"]; hasRequests {
			return true
		}
		return false
	} else if fingerprintType == "socket" {
		// Socket 指纹包含 network, tcp, udp 字段
		if _, hasNetwork := data["network"]; hasNetwork {
			return true
		}
		if _, hasTCP := data["tcp"]; hasTCP {
			return true
		}
		if _, hasUDP := data["udp"]; hasUDP {
			return true
		}
		return false
	}
	return false
}
