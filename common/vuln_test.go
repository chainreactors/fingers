package common

import "testing"

func TestVulnGetPayloadFormatsNonStringValues(t *testing.T) {
	vuln := &Vuln{
		Payload: map[string]interface{}{
			"key":   "value",
			"count": 1,
		},
	}

	got := vuln.GetPayload()
	want := " count:1  key:value "
	if got != want {
		t.Fatalf("GetPayload() = %q, want %q", got, want)
	}
}
