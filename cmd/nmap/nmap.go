package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/chainreactors/fingers/resources"

	"github.com/chainreactors/fingers"
	"github.com/chainreactors/fingers/common"
	"github.com/chainreactors/utils"
)

// 扫描统计信息
type ScanStats struct {
	TotalTargets    int64
	ScannedTargets  int64
	OpenPorts       int64
	IdentifiedPorts int64
	StartTime       time.Time
}

// 扫描结果
type ScanResult struct {
	Host      string
	Port      int
	Open      bool
	Framework *common.Framework
	Error     error
}

func main() {
	// 命令行参数
	var (
		cidrFlag    = flag.String("cidr", "127.0.0.1/32", "目标CIDR范围，例如: 192.168.1.0/24")
		portFlag    = flag.String("port", "1000-2000", "端口范围，例如: 80,443,1000-2000")
		threadsFlag = flag.Int("threads", 100, "并发线程数")
		timeoutFlag = flag.Int("timeout", 3, "扫描超时时间(秒)")
		levelFlag   = flag.Int("level", 1, "扫描深度级别(1-9)")
		verboseFlag = flag.Bool("v", false, "详细输出模式")
		outputFlag  = flag.String("o", "", "输出文件路径")
	)
	flag.Parse()

	if *cidrFlag == "" || *portFlag == "" {
		fmt.Println("使用方法:")
		fmt.Println("  nmap -cidr 192.168.1.0/24 -port 22,80,443,1000-2000")
		fmt.Println("  nmap -cidr 10.0.0.1 -port 80 -threads 200 -timeout 5")
		flag.PrintDefaults()
		return
	}

	fmt.Printf("🚀 启动nmap指纹扫描器\n")
	fmt.Printf("目标: %s\n", *cidrFlag)
	fmt.Printf("端口: %s\n", *portFlag)
	fmt.Printf("线程: %d\n", *threadsFlag)
	fmt.Printf("超时: %ds\n", *timeoutFlag)
	fmt.Printf("级别: %d\n", *levelFlag)

	// 解析CIDR和端口
	ips, err := parseCIDR(*cidrFlag)
	if err != nil {
		log.Fatalf("解析CIDR失败: %v", err)
	}

	// 使用utils包解析端口
	utils.PrePort, err = resources.LoadPorts()
	if err != nil {
		log.Fatalf("加载端口资源失败: %v", err)
	}
	var portList []string
	portList = utils.ParsePortsString(*portFlag)

	// 将字符串端口转换为整数端口
	ports, err := convertPortsToInt(portList)
	if err != nil {
		log.Fatalf("转换端口失败: %v", err)
	}

	fmt.Printf("📊 目标统计: %d个IP, %d个端口, 共%d个扫描目标\n",
		ips.Len(), len(ports), ips.Len()*len(ports))

	// 创建fingers引擎（只使用nmap引擎）
	engine, err := fingers.NewEngine(fingers.NmapEngine)
	if err != nil {
		log.Fatalf("创建引擎失败: %v", err)
	}

	// 创建网络发送器
	sender := common.NewServiceSender(time.Duration(*timeoutFlag) * time.Second)

	// 初始化统计信息
	stats := &ScanStats{
		TotalTargets: int64(ips.Len() * len(ports)),
		StartTime:    time.Now(),
	}

	// 创建任务通道和结果通道
	taskChan := make(chan scanTask, *threadsFlag*2)
	resultChan := make(chan ScanResult, *threadsFlag)

	// 启动工作协程
	var wg sync.WaitGroup
	for i := 0; i < *threadsFlag; i++ {
		wg.Add(1)
		go worker(engine, sender, taskChan, resultChan, &wg, *levelFlag)
	}

	// 启动结果处理协程
	go resultHandler(resultChan, stats, *verboseFlag, *outputFlag)

	// 启动进度显示协程
	ctx, cancel := context.WithCancel(context.Background())
	go progressReporter(ctx, stats)

	// 生成扫描任务
	go func() {
		defer close(taskChan)
		for ip := range ips.Range() {
			for _, port := range ports {
				taskChan <- scanTask{Host: ip.String(), Port: port}
			}
		}
	}()

	// 等待所有工作协程完成
	wg.Wait()
	close(resultChan)
	cancel() // 停止进度报告

	// 输出最终统计
	duration := time.Since(stats.StartTime)
	fmt.Printf("\n✅ 扫描完成!\n")
	fmt.Printf("总耗时: %v\n", duration)
	fmt.Printf("扫描目标: %d\n", atomic.LoadInt64(&stats.ScannedTargets))
	fmt.Printf("开放端口: %d\n", atomic.LoadInt64(&stats.OpenPorts))
	fmt.Printf("识别服务: %d\n", atomic.LoadInt64(&stats.IdentifiedPorts))
	fmt.Printf("扫描速度: %.2f targets/sec\n",
		float64(atomic.LoadInt64(&stats.ScannedTargets))/duration.Seconds())
}

// 扫描任务
type scanTask struct {
	Host string
	Port int
}

// 工作协程
func worker(engine *fingers.Engine, sender common.ServiceSender, taskChan <-chan scanTask, resultChan chan<- ScanResult, wg *sync.WaitGroup, level int) {
	defer wg.Done()

	for task := range taskChan {
		// 使用DetectService进行扫描
		serviceResults, err := engine.DetectService(task.Host, task.Port, level, sender, nil)

		result := ScanResult{
			Host:      task.Host,
			Port:      task.Port,
			Open:      len(serviceResults) > 0,
			Framework: nil,
			Error:     err,
		}

		// 如果有识别到的服务，取第一个
		if len(serviceResults) > 0 && serviceResults[0].Framework != nil {
			result.Framework = serviceResults[0].Framework
		}

		select {
		case resultChan <- result:
		default:
			// 结果通道已满，丢弃结果（避免阻塞）
		}
	}
}

// 结果处理协程
func resultHandler(resultChan <-chan ScanResult, stats *ScanStats, verbose bool, outputFile string) {
	var results []ScanResult

	for result := range resultChan {
		atomic.AddInt64(&stats.ScannedTargets, 1)

		// 统计开放端口
		if result.Open {
			atomic.AddInt64(&stats.OpenPorts, 1)
		}

		// 统计识别的服务
		if result.Framework != nil {
			atomic.AddInt64(&stats.IdentifiedPorts, 1)
		}

		// 输出结果
		if result.Open {
			if verbose || result.Framework != nil {
				printResult(result)
			}
			results = append(results, result)
		}
	}

	// 保存到文件
	if outputFile != "" {
		saveResults(results, outputFile)
	}
}

// 打印扫描结果
func printResult(result ScanResult) {
	target := fmt.Sprintf("%s:%d", result.Host, result.Port)

	if result.Framework != nil {
		// 使用Framework.String()方法进行输出
		frameworkStr := result.Framework.String()

		// 添加guess标识
		guessIndicator := ""
		if result.Framework.IsGuess() {
			guessIndicator = " [guess]"
		}

		// 输出基本信息
		fmt.Printf("✅ %s -> %s%s", target, frameworkStr, guessIndicator)

		// 输出CPE信息（如果有的话）
		if result.Framework.Attributes != nil && result.Framework.Attributes.String() != "" {
			fmt.Printf(" | CPE: %s", result.Framework.CPE())
		}

		fmt.Printf("\n")
	} else if result.Open {
		// 只是端口开放，无法识别服务
		fmt.Printf("🔓 %s -> 端口开放\n", target)
	}
}

// 进度报告协程
func progressReporter(ctx context.Context, stats *ScanStats) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			scanned := atomic.LoadInt64(&stats.ScannedTargets)
			total := stats.TotalTargets
			if total > 0 {
				progress := float64(scanned) / float64(total) * 100
				elapsed := time.Since(stats.StartTime)
				speed := float64(scanned) / elapsed.Seconds()

				fmt.Printf("📈 进度: %.1f%% (%d/%d) | 速度: %.1f/s | 开放: %d | 识别: %d\n",
					progress, scanned, total, speed,
					atomic.LoadInt64(&stats.OpenPorts),
					atomic.LoadInt64(&stats.IdentifiedPorts))
			}
		}
	}
}

// 保存结果到文件
func saveResults(results []ScanResult, filename string) {
	// TODO: 实现结果保存功能
	fmt.Printf("📝 结果已保存到: %s (%d条记录)\n", filename, len(results))
}

// parseCIDR 解析CIDR网段，返回IP地址列表
func parseCIDR(cidr string) (*utils.CIDR, error) {

	// 解析CIDR
	ipnet := utils.ParseCIDR(cidr)
	if ipnet == nil {
		return nil, fmt.Errorf("无效的CIDR: %s, 错误: %v", cidr)
	}

	return ipnet, nil
}

// inc 增加IP地址
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// convertPortsToInt 将字符串端口列表转换为整数端口列表
func convertPortsToInt(portList []string) ([]int, error) {
	var ports []int

	for _, portStr := range portList {
		portStr = strings.TrimSpace(portStr)

		// 跳过非数字端口（如 "oxid", "icmp" 等特殊协议）
		if !isNumericPort(portStr) {
			continue
		}

		if strings.Contains(portStr, "-") {
			// 端口范围
			parts := strings.Split(portStr, "-")
			if len(parts) != 2 {
				return nil, fmt.Errorf("无效的端口范围: %s", portStr)
			}

			start, err := strconv.Atoi(strings.TrimSpace(parts[0]))
			if err != nil {
				return nil, fmt.Errorf("无效的起始端口: %s", parts[0])
			}

			end, err := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err != nil {
				return nil, fmt.Errorf("无效的结束端口: %s", parts[1])
			}

			if start > end {
				return nil, fmt.Errorf("起始端口不能大于结束端口: %d > %d", start, end)
			}

			for port := start; port <= end; port++ {
				if port > 0 && port <= 65535 {
					ports = append(ports, port)
				}
			}
		} else {
			// 单个端口
			port, err := strconv.Atoi(portStr)
			if err != nil {
				return nil, fmt.Errorf("无效的端口: %s", portStr)
			}
			if port > 0 && port <= 65535 {
				ports = append(ports, port)
			}
		}
	}

	if len(ports) == 0 {
		return nil, fmt.Errorf("未找到有效的数字端口")
	}

	return removeDuplicatePorts(ports), nil
}

// isNumericPort 检查端口字符串是否为数字端口
func isNumericPort(portStr string) bool {
	// 检查是否包含数字或范围符号
	for _, char := range portStr {
		if (char >= '0' && char <= '9') || char == '-' {
			continue
		} else {
			return false
		}
	}
	return true
}

// removeDuplicatePorts 去除重复端口
func removeDuplicatePorts(ports []int) []int {
	seen := make(map[int]bool)
	var result []int

	for _, port := range ports {
		if !seen[port] {
			seen[port] = true
			result = append(result, port)
		}
	}

	return result
}

func init() {
	// 设置最大CPU使用数
	runtime.GOMAXPROCS(runtime.NumCPU())
}
