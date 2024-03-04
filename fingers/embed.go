//go:build !noembed && go1.16
// +build !noembed,go1.16

package fingers

import _ "embed"

//go:embed fingers.json
var FingerData []byte
