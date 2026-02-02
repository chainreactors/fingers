//go:build !go1.16 || noembed
// +build !go1.16 noembed

package resources

import (
	"github.com/chainreactors/utils"
	"gopkg.in/yaml.v3"
)

var AliasesData []byte

var PortData []byte // json format
var PrePort *utils.PortPreset

func LoadPorts() (*utils.PortPreset, error) {
	var ports []*utils.PortConfig
	var err error
	err = yaml.Unmarshal(PortData, &ports)
	if err != nil {
		return nil, err
	}

	PrePort = utils.NewPortPreset(ports)
	return PrePort, nil
}

// engine
var FingersHTTPData []byte
var FingersSocketData []byte

var GobyData []byte
var FingerprinthubWebData []byte
var FingerprinthubServiceData []byte
var EholeData []byte
var WappalyzerData []byte
var NmapServiceProbesData []byte
var NmapServicesData []byte

var CheckSum = map[string]string{}
