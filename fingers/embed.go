//go:build !noembed && go1.16
// +build !noembed,go1.16

package fingers

import _ "embed"

//go:embed http.json
var HTTPFingerData []byte

//go:embed socket.json
var SocketFingerData []byte
