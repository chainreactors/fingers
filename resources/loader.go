package resources

import (
	"fmt"
	"io/ioutil"
	"os"

	"gopkg.in/yaml.v3"
)

// LoadResource loads content from file path or URL.
// URL loading requires the non-passive build (see loader_http.go).
func LoadResource(path string) ([]byte, error) {
	if _, err := os.Stat(path); err == nil {
		return ioutil.ReadFile(path)
	}

	return loadRemote(path)
}

// LoadFingersFromYAML loads fingerprints from YAML format file or URL.
func LoadFingersFromYAML(path string) ([]byte, error) {
	content, err := LoadResource(path)
	if err != nil {
		return nil, err
	}

	var test interface{}
	if err := yaml.Unmarshal(content, &test); err != nil {
		return nil, fmt.Errorf("invalid YAML format: %w", err)
	}

	return content, nil
}
