//go:build !noembed && go1.16
// +build !noembed,go1.16

package wappalyzer

import _ "embed"

//go:embed fingerprints_data.json
var WappalyzerData []byte
