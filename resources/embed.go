//go:build !noembed && go1.16
// +build !noembed,go1.16

package resources

import (
	_ "embed"
	"github.com/chainreactors/utils"
	"gopkg.in/yaml.v3"
)

//go:embed aliases.yaml
var AliasesData []byte

//go:embed port.yaml
var PortData []byte // yaml format

var PrePort *utils.PortPreset

func LoadPorts() error {
	var ports []*utils.PortConfig
	var err error
	err = yaml.Unmarshal(PortData, &ports)
	if err != nil {
		return err
	}

	PrePort = utils.NewPortPreset(ports)
	return nil
}
