//go:build !noembed
// +build !noembed

package fingers

import (
	"io/ioutil"
)

func init() {
	var err error
	FingerData, err = ioutil.ReadFile("fingers.json")
	if err != nil {
		panic(err)
	}
}
