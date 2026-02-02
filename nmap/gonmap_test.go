package gonmap

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/chainreactors/fingers/common"
	"github.com/chainreactors/fingers/resources"
)

// TestParseLogic 测试解析逻辑
func TestParseLogic(t *testing.T) {
	// 读取原始文本文件
	content, err := os.ReadFile("../resources/nmap-service-probes.txt")
	if err != nil {
		t.Fatalf("Failed to read file: %v", err)
	}

	fmt.Printf("\n=== 解析逻辑测试 ===\n")

	// 统计原始文件中的Probe行数
	lines := strings.Split(string(content), "\n")
	probeLineCount := 0
	tcpProbeCount := 0
	udpProbeCount := 0

	for _, line := range lines {
		if strings.HasPrefix(line, "Probe TCP") {
			tcpProbeCount++
			probeLineCount++
		} else if strings.HasPrefix(line, "Probe UDP") {
			udpProbeCount++
			probeLineCount++
		}
	}

	fmt.Printf("原始文件统计:\n")
	fmt.Printf("  - Probe行总数: %d\n", probeLineCount)
	fmt.Printf("  - TCP Probe: %d\n", tcpProbeCount)
	fmt.Printf("  - UDP Probe: %d\n", udpProbeCount)

	// 使用TempParser解析
	parser := NewTempParser(string(content))
	probes := parser.GetProbes()

	fmt.Printf("\n解析结果:\n")
	fmt.Printf("  - 解析出的Probe数量: %d\n", len(probes))

	// 统计解析出的TCP和UDP probe
	parsedTCP := 0
	parsedUDP := 0
	for _, probe := range probes {
		if strings.HasPrefix(probe.Name, "TCP_") {
			parsedTCP++
		} else if strings.HasPrefix(probe.Name, "UDP_") {
			parsedUDP++
		}
	}

	fmt.Printf("  - TCP Probe: %d\n", parsedTCP)
	fmt.Printf("  - UDP Probe: %d\n", parsedUDP)

	// 检查是否有差异
	if probeLineCount != len(probes) {
		fmt.Printf("\n⚠️  警告: 原始文件有%d个Probe行，但只解析出%d个Probe\n", probeLineCount, len(probes))
		fmt.Printf("差异: %d个Probe未被解析\n", probeLineCount-len(probes))
	} else {
		fmt.Printf("\n✓ 解析完整，所有Probe都被正确解析\n")
	}
}
func TestJSONDataStructure(t *testing.T) {
	// 解压缩数据
	decompressedProbes, err := resources.DecompressGzip(resources.NmapServiceProbesData)
	if err != nil {
		t.Fatalf("Failed to decompress probes data: %v", err)
	}

	decompressedServices, err := resources.DecompressGzip(resources.NmapServicesData)
	if err != nil {
		t.Fatalf("Failed to decompress services data: %v", err)
	}

	// 直接解析JSON查看原始数据
	var data NmapProbesData
	if err := json.Unmarshal(decompressedProbes, &data); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	// 解析services数据
	var servicesData ServicesData
	if err := json.Unmarshal(decompressedServices, &servicesData); err != nil {
		t.Fatalf("Failed to unmarshal services JSON: %v", err)
	}

	fmt.Printf("\n=== JSON Data Structure ===\n")
	fmt.Printf("Probes in JSON: %d\n", len(data.Probes))
	fmt.Printf("Services in JSON: %d\n", len(servicesData.Services))
	fmt.Printf("Decompressed probes size: %d bytes\n", len(decompressedProbes))
	fmt.Printf("Decompressed services size: %d bytes\n", len(decompressedServices))

	// 统计match总数
	totalMatches := 0
	totalSoftMatches := 0
	for _, probe := range data.Probes {
		for _, match := range probe.MatchGroup {
			if match.Soft {
				totalSoftMatches++
			}
		}
		totalMatches += len(probe.MatchGroup)
	}
	fmt.Printf("\nTotal match rules: %d\n", totalMatches)
	fmt.Printf("  - Hard matches: %d\n", totalMatches-totalSoftMatches)
	fmt.Printf("  - Soft matches: %d\n", totalSoftMatches)
}

func TestScan(t *testing.T) {
	engine, err := NewNmapEngine(resources.NmapServiceProbesData, resources.NmapServicesData)
	if err != nil {
		t.Fatalf("Failed to create nmap engine: %v", err)
	}

	// Test port 135 MSRPC detection
	fmt.Println("=== Testing Port 135 MSRPC Detection ===")
	res := engine.ServiceMatch("127.0.0.1", "135", 2, common.NewServiceSender(time.Second*5), nil)

	if res != nil && res.Framework != nil {
		fmt.Printf("✓ Successfully detected service on port 135\n")
		fmt.Printf("  Service: %s, Product: %s\n", res.Framework.Name, res.Framework.Product)
	} else {
		fmt.Println("⚠ No service detected on port 135 (may not be running)")
	}
}

// TestNoGuessFlag verifies that the NoGuess flag is respected
func TestNoGuessFlag(t *testing.T) {
	engine, err := NewNmapEngine(resources.NmapServiceProbesData, resources.NmapServicesData)
	if err != nil {
		t.Fatalf("Failed to create nmap engine: %v", err)
	}

	fmt.Println("\n=== Testing NoGuess Flag Behavior ===")

	// Save original NoGuess value and restore after test
	originalNoGuess := common.NoGuess
	defer func() {
		common.NoGuess = originalNoGuess
	}()

	// Test 1: NoGuess = false (default) - guess should work
	fmt.Println("\n1. Testing with NoGuess = false (guess enabled)")
	common.NoGuess = false

	// Test against a high port that's unlikely to be running but might be guessable
	// Using port 9999 which is unlikely to have a service but has a guess entry
	res1 := engine.ServiceMatch("127.0.0.1", "9999", 1, common.NewServiceSender(time.Second*2), nil)
	if res1 != nil && res1.Framework != nil && res1.Framework.IsGuess() {
		fmt.Printf("   ✓ Guess result returned: %s (from: %s)\n", res1.Framework.Name, res1.Framework.From.String())
	} else {
		fmt.Println("   ⚠ No guess result (port may be closed or matched exactly)")
	}

	// Test 2: NoGuess = true - guess should be skipped
	fmt.Println("\n2. Testing with NoGuess = true (guess disabled)")
	common.NoGuess = true

	res2 := engine.ServiceMatch("127.0.0.1", "9999", 1, common.NewServiceSender(time.Second*2), nil)
	if res2 == nil {
		fmt.Println("   ✓ No result returned when NoGuess is true (correct behavior)")
	} else if res2.Framework != nil && !res2.Framework.IsGuess() {
		fmt.Printf("   ✓ Non-guess result returned: %s (from: %s)\n", res2.Framework.Name, res2.Framework.From.String())
	} else if res2.Framework != nil && res2.Framework.IsGuess() {
		t.Errorf("   ✗ Guess result returned when NoGuess is true (incorrect behavior)")
	}

	fmt.Println("\n✓ NoGuess flag test completed")
}

// TestProbeDataIntegrity verifies that binary probe data is correctly preserved
func TestProbeDataIntegrity(t *testing.T) {
	n := &Nmap{
		probeNameMap:      make(map[string]*Probe),
		rarityProbeMap:    make(map[int][]*Probe),
		portProbeMap:      make(map[int]ProbeList),
		sslSecondProbeMap: make(ProbeList, 0),
		sslProbeMap:       make(ProbeList, 0),
	}

	// 解压缩数据
	decompressedProbes, err := resources.DecompressGzip(resources.NmapServiceProbesData)
	if err != nil {
		t.Fatalf("Failed to decompress probes data: %v", err)
	}

	decompressedServices, err := resources.DecompressGzip(resources.NmapServicesData)
	if err != nil {
		t.Fatalf("Failed to decompress services data: %v", err)
	}

	n.loadProbesFromBytes(decompressedProbes)
	n.loadServicesFromBytes(decompressedServices)

	// 输出探针统计信息
	fmt.Printf("\n=== Probe Statistics ===\n")
	fmt.Printf("Total probes loaded: %d\n", len(n.probeNameMap))
	fmt.Printf("Decompressed probes data size: %d bytes\n", len(decompressedProbes))
	fmt.Printf("Decompressed services data size: %d bytes\n", len(decompressedServices))

	// 统计match总数
	totalMatches := 0
	for _, probe := range n.probeNameMap {
		totalMatches += len(probe.MatchGroup)
	}
	fmt.Printf("Total match rules: %d\n", totalMatches)

	// 列出前10个探针名称及其match数量
	fmt.Printf("\nFirst 10 probes with match counts:\n")
	count := 0
	for name, probe := range n.probeNameMap {
		if count >= 10 {
			break
		}
		fmt.Printf("  - %s: %d matches\n", name, len(probe.MatchGroup))
		count++
	}

	// Verify SMBProgNeg probe data integrity
	probe, exists := n.probeNameMap["TCP_SMBProgNeg"]
	if !exists {
		t.Fatal("TCP_SMBProgNeg probe not found")
	}

	// Check data length (should be 168 bytes for SMBProgNeg)
	fmt.Printf("\nSMBProgNeg probe SendRaw length: %d bytes\n", len(probe.SendRaw))
	if len(probe.SendRaw) != 168 {
		t.Errorf("Expected probe data length 168, got %d", len(probe.SendRaw))
	}

	// Check for UTF-8 replacement characters (0xef 0xbf 0xbd)
	// These indicate corrupted binary data
	for i := 0; i < len(probe.SendRaw)-2; i++ {
		if probe.SendRaw[i] == 0xef && probe.SendRaw[i+1] == 0xbf && probe.SendRaw[i+2] == 0xbd {
			t.Errorf("Found UTF-8 replacement character at position %d - binary data is corrupted", i)
		}
	}

	// Verify specific bytes that should be present (0xa4 and 0xff from SMB header)
	if probe.SendRaw[3] != 0xa4 {
		t.Errorf("Expected byte 0xa4 at position 3, got 0x%02x", probe.SendRaw[3])
	}
	if probe.SendRaw[4] != 0xff {
		t.Errorf("Expected byte 0xff at position 4, got 0x%02x", probe.SendRaw[4])
	}
}
