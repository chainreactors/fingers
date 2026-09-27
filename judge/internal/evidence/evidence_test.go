package evidence

import "testing"

func TestGenericName(t *testing.T) {
	for key, generic := range map[string]bool{
		NormalizeName("404 Not Found"):   true,
		NormalizeName("403 Forbidden"):   true,
		NormalizeName("502 Bad Gateway"): true,
		NormalizeName("Forbidden"):       true,
		NormalizeName("login"):           true,
		NormalizeName("SearXNG"):         false,
		NormalizeName("404 Tools"):       false,
	} {
		if GenericName(key) != generic {
			t.Errorf("GenericName(%q) = %v", key, !generic)
		}
	}
}
