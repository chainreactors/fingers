package fingers

import (
	"testing"

	"github.com/chainreactors/fingers/resources"
)

func TestKeywordIndex_FastPath(t *testing.T) {
	httpfs, err := LoadFingers(resources.FingersHTTPData)
	if err != nil {
		t.Fatalf("Failed to load HTTP fingers: %v", err)
	}
	for _, f := range httpfs {
		f.Compile(false)
	}

	idx := NewKeywordIndex(httpfs)

	total := len(httpfs)
	fastCount := len(idx.fastPath)

	t.Logf("Total HTTP fingers: %d", total)
	t.Logf("Fast-path fingers:  %d (%.1f%%)", fastCount, float64(fastCount)/float64(total)*100)
	t.Logf("Slow-path fingers:  %d (%.1f%%)", total-fastCount, float64(total-fastCount)/float64(total)*100)

	if fastCount == 0 {
		t.Error("No fast-path fingers found — optimization provides no benefit")
	}
}

func TestACPassiveMatch_Consistency(t *testing.T) {
	httpfs, err := LoadFingers(resources.FingersHTTPData)
	if err != nil {
		t.Fatalf("Failed to load HTTP fingers: %v", err)
	}
	for _, f := range httpfs {
		f.Compile(false)
	}

	idx := NewKeywordIndex(httpfs)

	responses := []struct {
		name string
		raw  string
	}{
		{
			"nginx",
			"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Type: text/html\r\n\r\n<html><body>Welcome to nginx!</body></html>",
		},
		{
			"apache",
			"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\nContent-Type: text/html\r\n\r\n<html><body>It works!</body></html>",
		},
		{
			"wordpress",
			"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/html\r\n\r\n<html><head><meta name=\"generator\" content=\"WordPress 5.8\" /></head><body>Blog</body></html>",
		},
		{
			"empty",
			"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body>Hello</body></html>",
		},
	}

	for _, tc := range responses {
		t.Run(tc.name, func(t *testing.T) {
			input := NewContent([]byte(tc.raw), "", true)

			baseFrames, baseVulns := httpfs.PassiveMatch(input, false)
			acFrames, acVulns := httpfs.ACPassiveMatch(input, idx, false)

			if len(baseFrames) != len(acFrames) {
				t.Errorf("Framework count: baseline=%d ac=%d", len(baseFrames), len(acFrames))
				t.Logf("Baseline: %v", baseFrames)
				t.Logf("AC:       %v", acFrames)
				return
			}

			for name := range baseFrames {
				if _, ok := acFrames[name]; !ok {
					t.Errorf("Missing in AC result: %s", name)
				}
			}
			for name := range acFrames {
				if _, ok := baseFrames[name]; !ok {
					t.Errorf("Extra in AC result: %s", name)
				}
			}

			t.Logf("Matched %d frameworks, %d vulns", len(acFrames), len(acVulns))
			_ = baseVulns
		})
	}
}

func BenchmarkPassiveMatch_Baseline(b *testing.B) {
	httpfs, err := LoadFingers(resources.FingersHTTPData)
	if err != nil {
		b.Fatalf("Failed to load: %v", err)
	}
	for _, f := range httpfs {
		f.Compile(false)
	}

	input := NewContent([]byte("HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Type: text/html\r\n\r\n<html><head><meta name=\"generator\" content=\"WordPress 5.8\" /></head><body>Blog</body></html>"), "", true)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		httpfs.PassiveMatch(input, false)
	}
}

func BenchmarkPassiveMatch_WithAC(b *testing.B) {
	httpfs, err := LoadFingers(resources.FingersHTTPData)
	if err != nil {
		b.Fatalf("Failed to load: %v", err)
	}
	for _, f := range httpfs {
		f.Compile(false)
	}
	idx := NewKeywordIndex(httpfs)

	input := NewContent([]byte("HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Type: text/html\r\n\r\n<html><head><meta name=\"generator\" content=\"WordPress 5.8\" /></head><body>Blog</body></html>"), "", true)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		httpfs.ACPassiveMatch(input, idx, false)
	}
}
