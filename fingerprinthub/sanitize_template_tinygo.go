//go:build tinygo
// +build tinygo

package fingerprinthub

import "strings"

func sanitizeTemplateForTinyGo(rawTemplate map[string]interface{}) {
	sanitizeTemplateValue(rawTemplate)
}

func sanitizeTemplateValue(v interface{}) interface{} {
	switch value := v.(type) {
	case map[string]interface{}:
		for k, item := range value {
			value[k] = sanitizeTemplateValue(item)
		}
		return value
	case []interface{}:
		for i, item := range value {
			value[i] = sanitizeTemplateValue(item)
		}
		return value
	case string:
		return strings.TrimPrefix(value, "(?x)")
	default:
		return value
	}
}
