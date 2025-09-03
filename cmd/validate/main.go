package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/chainreactors/fingers/fingers"
	"github.com/invopop/jsonschema"
	"gopkg.in/yaml.v3"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: validate <path_or_file> [options]")
		fmt.Println("Options:")
		fmt.Println("  -schema    Output JSON schema for fingers fingerprint format")
		fmt.Println("")
		fmt.Println("Examples:")
		fmt.Println("  validate fingerprint.json")
		fmt.Println("  validate ./fingerprints/")
		fmt.Println("  validate -schema")
		return
	}

	target := os.Args[1]

	// Handle schema output
	if target == "-schema" {
		if err := outputSchema(); err != nil {
			fmt.Printf("Error generating schema: %s\n", err.Error())
			os.Exit(1)
		}
		return
	}

	// Validate files
	err := filepath.Walk(target, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Check for supported file extensions
		ext := filepath.Ext(path)
		if ext != ".yaml" && ext != ".yml" && ext != ".json" {
			return nil
		}

		fmt.Printf("Validating: %s\n", path)

		// Read file content
		content, err := ioutil.ReadFile(path)
		if err != nil {
			fmt.Printf("❌ %s - Failed to read file: %s\n", path, err.Error())
			return nil
		}

		// Convert to JSON for validation
		var data interface{}
		if ext == ".json" {
			err = json.Unmarshal(content, &data)
		} else {
			err = yaml.Unmarshal(content, &data)
		}
		
		if err != nil {
			fmt.Printf("❌ %s - Failed to parse file: %s\n", path, err.Error())
			return nil
		}

		// Convert to JSON bytes for schema validation
		jsonData, err := json.Marshal(data)
		if err != nil {
			fmt.Printf("❌ %s - Failed to convert to JSON: %s\n", path, err.Error())
			return nil
		}

		// Validate against schema
		validCount, totalCount, fingerResults := validateAgainstSchema(jsonData)
		
		// Print detailed results
		fmt.Printf("📁 %s (%d fingerprints)\n", path, totalCount)
		
		for _, result := range fingerResults {
			if result.Valid {
				fmt.Printf("  ✅ %s - Valid\n", result.Name)
			} else {
				fmt.Printf("  ❌ %s - %s\n", result.Name, result.Error)
			}
		}
		
		// Print summary
		if validCount == totalCount && totalCount > 0 {
			fmt.Printf("  📊 Summary: All %d fingerprints valid\n\n", totalCount)
		} else if validCount > 0 {
			fmt.Printf("  📊 Summary: %d/%d fingerprints valid\n\n", validCount, totalCount)
		} else {
			fmt.Printf("  📊 Summary: No valid fingerprints\n\n")
		}
		return nil
	})

	if err != nil {
		fmt.Printf("Error during validation: %s\n", err.Error())
		os.Exit(1)
	}
}

type FingerprintResult struct {
	Name  string
	Valid bool
	Error string
}

func validateAgainstSchema(jsonData []byte) (validCount, totalCount int, results []FingerprintResult) {
	// First try as single fingerprint
	var singleFinger fingers.Finger
	if err := json.Unmarshal(jsonData, &singleFinger); err == nil {
		// Single fingerprint case
		totalCount = 1
		result := FingerprintResult{
			Name:  singleFinger.Name,
			Valid: true,
		}
		
		if singleFinger.Name == "" {
			result.Name = "<unnamed>"
			result.Valid = false
			result.Error = "name is required"
		} else if len(singleFinger.Rules) == 0 {
			result.Valid = false
			result.Error = "must have at least one rule"
		}
		
		if result.Valid {
			validCount = 1
		}
		results = append(results, result)
		return
	}

	// Try as array of fingerprints
	var fingerArray []fingers.Finger
	if err := json.Unmarshal(jsonData, &fingerArray); err == nil {
		// Array of fingerprints case
		totalCount = len(fingerArray)
		for i, finger := range fingerArray {
			result := FingerprintResult{
				Name:  finger.Name,
				Valid: true,
			}
			
			if finger.Name == "" {
				result.Name = fmt.Sprintf("<unnamed-%d>", i)
				result.Valid = false
				result.Error = "name is required"
			} else if len(finger.Rules) == 0 {
				result.Valid = false
				result.Error = "must have at least one rule"
			}
			
			if result.Valid {
				validCount++
			}
			results = append(results, result)
		}
		return
	}

	// If neither single nor array format works
	results = append(results, FingerprintResult{
		Name:  "<invalid>",
		Valid: false,
		Error: "data doesn't match fingers fingerprint format",
	})
	totalCount = 1
	return
}

func outputSchema() error {
	reflector := jsonschema.Reflector{
		AllowAdditionalProperties: false,
		DoNotReference:           true,
	}

	// Generate schema for single fingerprint
	schema := reflector.Reflect(&fingers.Finger{})
	schema.Title = "Fingers Fingerprint Schema"
	schema.Description = "JSON Schema for validating Fingers fingerprint library format"

	// Add examples
	schema.Examples = []interface{}{
		map[string]interface{}{
			"name":     "nginx",
			"vendor":   "nginx",
			"product":  "nginx",
			"protocol": "http",
			"link":     "https://nginx.org",
			"default_port": []string{"80", "443"},
			"focus":    false,
			"rule": []map[string]interface{}{
				{
					"regexps": map[string]interface{}{
						"header": []string{"Server: nginx"},
						"regexp": []string{"nginx/([\\d\\.]+)"},
					},
					"version": "\\1",
					"level":   0,
				},
			},
			"tag":   []string{"web", "server"},
			"opsec": false,
		},
	}

	schemaJSON, err := json.MarshalIndent(schema, "", "  ")
	if err != nil {
		return err
	}

	fmt.Println(string(schemaJSON))
	return nil
}