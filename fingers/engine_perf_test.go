package fingers

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"
	"time"

	"github.com/chainreactors/fingers/common"
	"github.com/chainreactors/fingers/resources"
)

const frontendMHTMLPath = "../frontend.mhtml"
const chunkSize16KB = 16 * 1024

var benchmarkFrontendMatchCount int

func loadFrontendMHTML(tb testing.TB) []byte {
	tb.Helper()

	absPath, err := filepath.Abs(frontendMHTMLPath)
	if err != nil {
		tb.Fatalf("failed to resolve %s: %v", frontendMHTMLPath, err)
	}

	content, err := os.ReadFile(frontendMHTMLPath)
	if err != nil {
		if os.IsNotExist(err) {
			tb.Skipf("test file not found: %s", absPath)
		}
		tb.Fatalf("failed to read %s: %v", absPath, err)
	}
	tb.Logf("loaded test file: %s (%d bytes)", absPath, len(content))
	return content
}

func newPerfEngine(tb testing.TB) *FingersEngine {
	tb.Helper()

	engine, err := NewFingersEngine(resources.FingersHTTPData, resources.FingersSocketData, resources.PortData)
	if err != nil {
		tb.Fatalf("failed to create fingers engine: %v", err)
	}
	return engine
}

func splitRawHTTP(content []byte) ([]byte, []byte, bool) {
	sepIndex := bytes.Index(content, []byte("\r\n\r\n"))
	if sepIndex == -1 {
		return nil, content, false
	}
	bodyOffset := sepIndex + len("\r\n\r\n")
	return content[:bodyOffset], content[bodyOffset:], true
}

func chunkedHTTPMatch(engine *FingersEngine, content []byte, chunkSize int) (common.Frameworks, common.Vulns, int) {
	frames := make(common.Frameworks)
	vulns := make(common.Vulns)

	header, body, hasHTTPHeader := splitRawHTTP(content)
	if len(body) == 0 {
		partFrames, partVulns := engine.HTTPMatch(content, "")
		frames.Merge(partFrames)
		vulns.Merge(partVulns)
		return frames, vulns, 1
	}

	chunks := 0
	for offset := 0; offset < len(body); offset += chunkSize {
		end := offset + chunkSize
		if end > len(body) {
			end = len(body)
		}

		part := body[offset:end]
		chunkContent := part
		if hasHTTPHeader {
			chunkContent = make([]byte, len(header)+len(part))
			copy(chunkContent, header)
			copy(chunkContent[len(header):], part)
		}

		partFrames, partVulns := engine.HTTPMatch(chunkContent, "")
		frames.Merge(partFrames)
		vulns.Merge(partVulns)
		chunks++
	}

	return frames, vulns, chunks
}

func frameworkNameDiff(left, right common.Frameworks) []string {
	diff := make([]string, 0)
	for name := range left {
		if _, ok := right[name]; !ok {
			diff = append(diff, name)
		}
	}
	sort.Strings(diff)
	return diff
}

func TestFingersEngine_FullMatchFrontendMHTMLCost(t *testing.T) {
	engine := newPerfEngine(t)
	content := loadFrontendMHTML(t)

	start := time.Now()
	frameworks, vulns := engine.HTTPMatch(content, "")
	elapsed := time.Since(start)

	t.Logf("single full HTTPMatch cost=%s, frameworks=%d, vulns=%d", elapsed, len(frameworks), len(vulns))
}

func TestFingersEngine_Chunk16KFrontendMHTMLCost(t *testing.T) {
	engine := newPerfEngine(t)
	content := loadFrontendMHTML(t)

	fullStart := time.Now()
	fullFrames, fullVulns := engine.HTTPMatch(content, "")
	fullElapsed := time.Since(fullStart)

	chunkStart := time.Now()
	chunkFrames, chunkVulns, chunkCount := chunkedHTTPMatch(engine, content, chunkSize16KB)
	chunkElapsed := time.Since(chunkStart)

	ratio := 0.0
	if fullElapsed > 0 {
		ratio = float64(chunkElapsed) / float64(fullElapsed)
	}

	fullOnly := frameworkNameDiff(fullFrames, chunkFrames)
	chunkOnly := frameworkNameDiff(chunkFrames, fullFrames)

	t.Logf("full HTTPMatch: cost=%s, frameworks=%d, vulns=%d", fullElapsed, len(fullFrames), len(fullVulns))
	t.Logf("chunked HTTPMatch(16KB): chunks=%d, cost=%s, frameworks=%d, vulns=%d, ratio_vs_full=%.2fx", chunkCount, chunkElapsed, len(chunkFrames), len(chunkVulns), ratio)
	t.Logf("framework diff: full_only=%d, chunk_only=%d", len(fullOnly), len(chunkOnly))
	if len(fullOnly) > 0 && len(fullOnly) <= 20 {
		t.Logf("full_only names: %v", fullOnly)
	}
	if len(chunkOnly) > 0 && len(chunkOnly) <= 20 {
		t.Logf("chunk_only names: %v", chunkOnly)
	}
}

func TestFingersEngine_ChunkSizeSweepFrontendMHTMLCost(t *testing.T) {
	engine := newPerfEngine(t)
	content := loadFrontendMHTML(t)

	runtime.GC()
	fullStart := time.Now()
	fullFrames, fullVulns := engine.HTTPMatch(content, "")
	fullElapsed := time.Since(fullStart)

	t.Logf("baseline full HTTPMatch: cost=%s, frameworks=%d, vulns=%d", fullElapsed, len(fullFrames), len(fullVulns))

	chunkSizes := []int{
		16 * 1024,
		32 * 1024,
		64 * 1024,
		128 * 1024,
		256 * 1024,
	}

	for _, chunkSize := range chunkSizes {
		runtime.GC()
		start := time.Now()
		frames, vulns, chunks := chunkedHTTPMatch(engine, content, chunkSize)
		elapsed := time.Since(start)

		ratio := 0.0
		if fullElapsed > 0 {
			ratio = float64(elapsed) / float64(fullElapsed)
		}

		fullOnly := frameworkNameDiff(fullFrames, frames)
		chunkOnly := frameworkNameDiff(frames, fullFrames)

		t.Logf(
			"chunk=%dKB: chunks=%d, cost=%s, ratio_vs_full=%.2fx, frameworks=%d, vulns=%d, full_only=%d, chunk_only=%d",
			chunkSize/1024, chunks, elapsed, ratio, len(frames), len(vulns), len(fullOnly), len(chunkOnly),
		)
	}
}

func TestFingersEngine_SmallChunkSweepFrontendMHTMLCost(t *testing.T) {
	engine := newPerfEngine(t)
	content := loadFrontendMHTML(t)

	runtime.GC()
	fullStart := time.Now()
	fullFrames, fullVulns := engine.HTTPMatch(content, "")
	fullElapsed := time.Since(fullStart)

	t.Logf("baseline full HTTPMatch: cost=%s, frameworks=%d, vulns=%d", fullElapsed, len(fullFrames), len(fullVulns))

	chunkSizes := []int{
		4 * 1024,
		8 * 1024,
	}

	for _, chunkSize := range chunkSizes {
		runtime.GC()
		start := time.Now()
		frames, vulns, chunks := chunkedHTTPMatch(engine, content, chunkSize)
		elapsed := time.Since(start)

		ratio := 0.0
		if fullElapsed > 0 {
			ratio = float64(elapsed) / float64(fullElapsed)
		}

		fullOnly := frameworkNameDiff(fullFrames, frames)
		chunkOnly := frameworkNameDiff(frames, fullFrames)

		t.Logf(
			"chunk=%dKB: chunks=%d, cost=%s, ratio_vs_full=%.2fx, frameworks=%d, vulns=%d, full_only=%d, chunk_only=%d",
			chunkSize/1024, chunks, elapsed, ratio, len(frames), len(vulns), len(fullOnly), len(chunkOnly),
		)
	}
}

func BenchmarkFingersEngine_FullMatchFrontendMHTML(b *testing.B) {
	engine := newPerfEngine(b)
	content := loadFrontendMHTML(b)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		frameworks, _ := engine.HTTPMatch(content, "")
		benchmarkFrontendMatchCount = len(frameworks)
	}
}

func BenchmarkFingersEngine_Chunk16KFrontendMHTML(b *testing.B) {
	engine := newPerfEngine(b)
	content := loadFrontendMHTML(b)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		frameworks, _, _ := chunkedHTTPMatch(engine, content, chunkSize16KB)
		benchmarkFrontendMatchCount = len(frameworks)
	}
}

func BenchmarkFingersEngine_ChunkSizeSweepFrontendMHTML(b *testing.B) {
	engine := newPerfEngine(b)
	content := loadFrontendMHTML(b)

	chunkSizes := []int{
		16 * 1024,
		32 * 1024,
		64 * 1024,
		128 * 1024,
		256 * 1024,
	}

	for _, chunkSize := range chunkSizes {
		chunkSize := chunkSize
		b.Run(fmt.Sprintf("%dKB", chunkSize/1024), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				frameworks, _, _ := chunkedHTTPMatch(engine, content, chunkSize)
				benchmarkFrontendMatchCount = len(frameworks)
			}
		})
	}
}
