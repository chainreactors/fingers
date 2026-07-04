//go:build passive_only
// +build passive_only

package fingerprinthub

import "github.com/chainreactors/fingers/common"

type activeState struct{}

func (engine *FingerPrintHubEngine) HTTPActiveMatch(baseURL string, level int, transport interface{}, callback func(*common.Framework, *common.Vuln)) (common.Frameworks, common.Vulns) {
	return nil, nil
}

func (engine *FingerPrintHubEngine) ServiceMatch(host string, portStr string, level int, sender common.ServiceSender, callback common.ServiceCallback) *common.ServiceResult {
	return nil
}
