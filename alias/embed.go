//go:build !noembed && go1.16
// +build !noembed,go1.16

package alias

import _ "embed"

//go:embed aliases.yaml
var AliasesData []byte
