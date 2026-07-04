//go:build !passive_only
// +build !passive_only

package resources

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

func loadRemote(path string) ([]byte, error) {
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		resp, err := http.Get(path)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch from URL: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("bad status: %s", resp.Status)
		}

		return ioutil.ReadAll(resp.Body)
	}

	return nil, fmt.Errorf("invalid resource path: %s (not a file or URL)", path)
}
