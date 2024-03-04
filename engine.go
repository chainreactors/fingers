package fingers

import (
	"github.com/chainreactors/fingers/fingerprinthub"
	"github.com/chainreactors/fingers/fingers"
	wappalyzer "github.com/chainreactors/fingers/wappalyzergo"
)

type Engine struct {
	FingersEngine     *fingers.FingersRules
	FingerPrintEngine *fingerprinthub.FingerPrintHubs
	WappalyzerEngine  *wappalyzer.Wappalyze
}
