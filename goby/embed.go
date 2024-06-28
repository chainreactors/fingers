//go:build !noembed && go1.16
// +build !noembed,go1.16

package goby

import _ "embed"

//go:embed goby.json
var GobyData []byte
