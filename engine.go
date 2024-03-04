package fingers

import (
	"github.com/chainreactors/fingers/fingerprinthub"
	"github.com/chainreactors/fingers/fingers"
	wappalyzer "github.com/chainreactors/fingers/wappalyzer"
)

func NewEngine() (*Engine, error) {
	engine := &Engine{}
	fingersEngine, err := fingers.NewFingersEngine(fingers.FingerData)
	if err != nil {
		return nil, err
	}
	engine.FingersEngine = fingersEngine

	fingerPrintEngine, err := fingerprinthub.NewFingerPrintHubEngine()
	if err != nil {
		return nil, err
	}
	engine.FingerPrintEngine = fingerPrintEngine

	wappalyzerEngine, err := wappalyzer.NewWappalyzeEngine()
	if err != nil {
		return nil, err
	}
	engine.WappalyzerEngine = wappalyzerEngine

	return engine, nil
}

type Engine struct {
	FingersEngine     *fingers.FingersRules
	FingerPrintEngine fingerprinthub.FingerPrintHubs
	WappalyzerEngine  *wappalyzer.Wappalyze
}
