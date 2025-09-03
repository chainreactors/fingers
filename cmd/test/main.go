package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/chainreactors/fingers/alias"
	"github.com/chainreactors/fingers/common"
	"github.com/chainreactors/fingers"
	"gopkg.in/yaml.v3"
)

func main() {
	var (
		aliasFile    = flag.String("alias", "", "Path to alias file")
		target       = flag.String("target", "", "Target URL or address to test")
		timeout      = flag.Int("timeout", 10, "Request timeout in seconds")
		verbose      = flag.Bool("verbose", false, "Enable verbose output")
		detectAll    = flag.Bool("detect-all", false, "Run general fingerprint detection on target (ignores alias filtering)")
		help         = flag.Bool("help", false, "Show help information")
	)

	flag.Parse()

	if *help {
		showHelp()
		return
	}

	if *target == "" {
		fmt.Println("Error: -target is required")
		showHelp()
		os.Exit(1)
	}

	// Initialize fingerprint engine
	eng, err := fingers.NewEngine()
	if err != nil {
		fmt.Printf("Error initializing engine: %s\n", err.Error())
		os.Exit(1)
	}

	fmt.Printf("🎯 Testing target: %s\n", *target)

	// If detect-all flag is set, run general detection
	if *detectAll {
		fmt.Println("🔍 Running general fingerprint detection...\n")
		allResults := runGeneralDetection(eng, *target, *timeout, *verbose)
		
		fmt.Printf("📊 General Detection Results:\n")
		if len(allResults) > 0 {
			fmt.Printf("   Found %d fingerprints:\n", len(allResults))
			for _, result := range allResults {
				fmt.Printf("   🎯 %s (%s) - %s\n", result.Name, result.From, result.Version)
			}
		} else {
			fmt.Println("   ❌ No fingerprints detected")
		}
		fmt.Println()
	}

	// Load and test aliases if alias file provided
	if *aliasFile != "" {
		aliases, err := loadAliasFile(*aliasFile)
		if err != nil {
			fmt.Printf("Error loading alias file: %s\n", err.Error())
			os.Exit(1)
		}

		fmt.Printf("📁 Loaded %d aliases from %s\n\n", len(aliases), *aliasFile)
		testAliasMatching(eng, *target, aliases, *timeout, *verbose)
	}
}

func runGeneralDetection(eng *fingers.Engine, target string, timeout int, verbose bool) []common.Framework {
	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
	}

	// Ensure target has protocol
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "http://" + target
	}

	if verbose {
		fmt.Printf("      🌐 Requesting: %s\n", target)
	}

	// Make HTTP request
	resp, err := client.Get(target)
	if err != nil {
		if verbose {
			fmt.Printf("      ❌ Request failed: %s\n", err.Error())
		}
		return nil
	}
	defer resp.Body.Close()

	// Detect frameworks
	frameworks, err := eng.DetectResponse(resp)
	if err != nil {
		if verbose {
			fmt.Printf("      ❌ Detection failed: %s\n", err.Error())
		}
		return nil
	}

	// Convert map to slice
	var results []common.Framework
	for _, framework := range frameworks {
		results = append(results, *framework)
	}

	return results
}

func testAliasMatching(eng *fingers.Engine, target string, aliases []alias.Alias, timeout int, verbose bool) {
	// Test each alias against the target
	var totalTests, successfulMatches int
	for _, aliasEntry := range aliases {
		if len(aliasEntry.Target) == 0 {
			if verbose {
				fmt.Printf("⏭️  Skipping %s - no target URLs defined\n", aliasEntry.Name)
			}
			continue
		}

		// Check if current target matches any of the alias targets
		targetMatched := false
		for _, aliasTarget := range aliasEntry.Target {
			if matchesTarget(target, aliasTarget) {
				targetMatched = true
				break
			}
		}

		if !targetMatched {
			if verbose {
				fmt.Printf("⏭️  Skipping %s - target doesn't match [%s]\n", 
					aliasEntry.Name, strings.Join(aliasEntry.Target, ", "))
			}
			continue
		}

		totalTests++
		fmt.Printf("🔍 Testing alias: %s (priority: %d)\n", aliasEntry.Name, aliasEntry.Priority)
		if aliasEntry.Label != "" {
			fmt.Printf("   📝 Labels: %s\n", aliasEntry.Label)
		}

		// Test fingerprint detection
		results := testFingerprintDetection(eng, target, aliasEntry, timeout, verbose)
		
		if len(results) > 0 {
			successfulMatches++
			fmt.Printf("   ✅ Found %d matching fingerprints:\n", len(results))
			for _, result := range results {
				fmt.Printf("      🎯 %s (%s) - %s\n", result.Name, result.From, result.Version)
			}
		} else {
			fmt.Printf("   ❌ No matching fingerprints detected\n")
		}
		fmt.Println()
	}

	// Summary
	fmt.Printf("📊 Alias Testing Summary:\n")
	fmt.Printf("   Total aliases tested: %d\n", totalTests)
	fmt.Printf("   Successful matches: %d\n", successfulMatches)
	if totalTests > 0 {
		fmt.Printf("   Success rate: %.1f%%\n", float64(successfulMatches)/float64(totalTests)*100)
	}
}

func showHelp() {
	fmt.Println("Fingers Alias Tester")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  test -target <target_url> [options]")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  -alias string")
	fmt.Println("        Path to alias YAML file (optional)")
	fmt.Println("  -target string")
	fmt.Println("        Target URL or address to test (e.g., https://example.com or 192.168.1.1:80)")
	fmt.Println("  -detect-all")
	fmt.Println("        Run general fingerprint detection on target (ignores alias filtering)")
	fmt.Println("  -timeout int")
	fmt.Println("        Request timeout in seconds (default 10)")
	fmt.Println("  -verbose")
	fmt.Println("        Enable verbose output")
	fmt.Println("  -help")
	fmt.Println("        Show this help information")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  # Run general fingerprint detection")
	fmt.Println("  test -target https://nginx.org -detect-all")
	fmt.Println()
	fmt.Println("  # Test a single target against aliases")
	fmt.Println("  test -target https://nginx.org -alias aliases.yaml")
	fmt.Println()
	fmt.Println("  # Test with verbose output")
	fmt.Println("  test -target 192.168.1.100:80 -alias aliases.yaml -verbose")
}

func loadAliasFile(filename string) ([]alias.Alias, error) {
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var aliases []alias.Alias
	if strings.HasSuffix(filename, ".json") {
		err = json.Unmarshal(content, &aliases)
	} else {
		err = yaml.Unmarshal(content, &aliases)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to parse file: %w", err)
	}

	return aliases, nil
}

func matchesTarget(currentTarget, aliasTarget string) bool {
	// Simple matching logic - can be enhanced
	// Extract domain/IP from URLs for comparison
	currentClean := extractHostFromTarget(currentTarget)
	aliasClean := extractHostFromTarget(aliasTarget)
	
	return strings.EqualFold(currentClean, aliasClean) || 
		   strings.Contains(strings.ToLower(currentTarget), strings.ToLower(aliasTarget)) ||
		   strings.Contains(strings.ToLower(aliasTarget), strings.ToLower(currentTarget))
}

func extractHostFromTarget(target string) string {
	// Remove protocol if present
	if strings.HasPrefix(target, "http://") {
		target = target[7:]
	} else if strings.HasPrefix(target, "https://") {
		target = target[8:]
	}
	
	// Remove path if present
	if idx := strings.Index(target, "/"); idx != -1 {
		target = target[:idx]
	}
	
	return target
}

func testFingerprintDetection(eng *fingers.Engine, target string, aliasEntry alias.Alias, timeout int, verbose bool) []common.Framework {
	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
	}

	// Ensure target has protocol
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "http://" + target
	}

	if verbose {
		fmt.Printf("      🌐 Requesting: %s\n", target)
	}

	// Make HTTP request
	resp, err := client.Get(target)
	if err != nil {
		if verbose {
			fmt.Printf("      ❌ Request failed: %s\n", err.Error())
		}
		return nil
	}
	defer resp.Body.Close()

	// Detect frameworks
	frameworks, err := eng.DetectResponse(resp)
	if err != nil {
		if verbose {
			fmt.Printf("      ❌ Detection failed: %s\n", err.Error())
		}
		return nil
	}

	// Filter results based on alias mappings
	var matchingFrameworks []common.Framework
	for _, framework := range frameworks {
		if isExpectedFramework(*framework, aliasEntry) {
			matchingFrameworks = append(matchingFrameworks, *framework)
		}
	}

	return matchingFrameworks
}

func isExpectedFramework(framework common.Framework, aliasEntry alias.Alias) bool {
	// Check if this framework matches any of the expected aliases
	engineName := framework.From.String()
	
	if expectedNames, exists := aliasEntry.AliasMap[engineName]; exists {
		for _, expectedName := range expectedNames {
			if strings.EqualFold(framework.Name, expectedName) ||
			   strings.Contains(strings.ToLower(framework.Name), strings.ToLower(expectedName)) {
				return true
			}
		}
	}
	
	return false
}