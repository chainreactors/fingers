//go:build passive_only
// +build passive_only

package resources

import "fmt"

func loadRemote(path string) ([]byte, error) {
	return nil, fmt.Errorf("remote loading not available in passive_only build: %s", path)
}
