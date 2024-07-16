//go:build !go1.16
// +build !go1.16

package resources

import (
	"encoding/json"
	"github.com/chainreactors/utils"
)

var AliasesData []byte

var PortData []byte // json format
var PrePort *utils.PortPreset

func LoadPorts() error {
	var ports []*utils.PortConfig
	var err error
	err = json.Unmarshal(PortData, &ports)
	if err != nil {
		return err
	}

	PrePort = utils.NewPortPreset(ports)
	return nil
}