//go:build !noembed && go1.16
// +build !noembed,go1.16

package ehole

import _ "embed"

//go:embed finger.json
var EholeData []byte
