//go:build !noembed && go1.16
// +build !noembed,go1.16

package fingerprinthub

import _ "embed"

//go:embed web_fingerprint_v3.json
var Fingerprinthubdata []byte
