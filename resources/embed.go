//go:build !noembed && go1.16
// +build !noembed,go1.16

package resources

import (
	_ "embed"
	"github.com/chainreactors/utils"
	"github.com/chainreactors/utils/encode"
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

// engine

var (
	//go:embed goby.json.gz
	GobyData []byte

	//go:embed fingerprinthub_v3.json.gz
	Fingerprinthubdata []byte

	//go:embed ehole.json.gz
	EholeData []byte

	//go:embed fingers_http.json.gz
	FingersHTTPData []byte

	//go:embed fingers_socket.json.gz
	FingersSocketData []byte

	//go:embed wappalyzer.json.gz
	WappalyzerData []byte

	CheckSum = map[string]string{
		"goby":           encode.Md5Hash(GobyData),
		"fingerprinthub": encode.Md5Hash(Fingerprinthubdata),
		"ehole":          encode.Md5Hash(EholeData),
		"fingers":        encode.Md5Hash(FingersHTTPData),
		"fingers_socket": encode.Md5Hash(FingersSocketData),
		"wappalyzer":     encode.Md5Hash(WappalyzerData),
		"alias":          encode.Md5Hash(AliasesData),
		"port":           encode.Md5Hash(PortData),
	}
)
