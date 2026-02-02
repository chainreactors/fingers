package gonmap

import (
	"fmt"
	"testing"
	"time"

	"github.com/chainreactors/fingers/common"
	"github.com/chainreactors/fingers/resources"
)

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

// TestProbeDataIntegrity verifies that binary probe data is correctly preserved
func TestProbeDataIntegrity(t *testing.T) {
	n := &Nmap{
		probeNameMap:      make(map[string]*Probe),
		rarityProbeMap:    make(map[int][]*Probe),
		portProbeMap:      make(map[int]ProbeList),
		sslSecondProbeMap: make(ProbeList, 0),
		sslProbeMap:       make(ProbeList, 0),
	}

	n.loadProbesFromBytes(resources.NmapServiceProbesData)
	n.loadServicesFromBytes(resources.NmapServicesData)

	// Verify SMBProgNeg probe data integrity
	probe, exists := n.probeNameMap["TCP_SMBProgNeg"]
	if !exists {
		t.Fatal("TCP_SMBProgNeg probe not found")
	}

	// Check data length (should be 168 bytes for SMBProgNeg)
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
