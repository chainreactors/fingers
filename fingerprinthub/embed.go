//go:build !noembed
// +build !noembed

package fingerprinthub

import "io/ioutil"

func init() {
	var err error
	fingerprinthubdata, err = ioutil.ReadFile("web_fingerprint_v3.json")
	if err != nil {
		panic(err)
	}
}
