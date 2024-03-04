//go:build !noembed
// +build !noembed

package wappalyzer

import "io/ioutil"

func init() {
	var err error
	fingerprints, err = ioutil.ReadFile("fingerprints_data.json")
	if err != nil {
		panic(err)
	}
}
