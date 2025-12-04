package resources

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// LoadResource loads content from file path or HTTP/HTTPS URL
func LoadResource(path string) ([]byte, error) {
	// Check if it's a local file
	if _, err := os.Stat(path); err == nil {
		return os.ReadFile(path)
	}

	// Check if it's a URL
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		resp, err := http.Get(path)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch from URL: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("bad status: %s", resp.Status)
		}

		return io.ReadAll(resp.Body)
	}

	return nil, fmt.Errorf("invalid resource path: %s (not a file or URL)", path)
}

// LoadFingersFromYAML loads fingerprints from YAML format file or URL
// This function is specifically for loading custom fingerprints in YAML format
func LoadFingersFromYAML(path string) ([]byte, error) {
	content, err := LoadResource(path)
	if err != nil {
		return nil, err
	}

	// Validate that it's valid YAML by attempting to unmarshal
	var test interface{}
	if err := yaml.Unmarshal(content, &test); err != nil {
		return nil, fmt.Errorf("invalid YAML format: %w", err)
	}

	return content, nil
}
