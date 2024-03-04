//go:build !noembed
// +build !noembed

package fingers

import _ "embed"

//go:embed fingers.json
var Fingersdata []byte
