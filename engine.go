package fingers

import (
	"bytes"
	"github.com/chainreactors/fingers/common"
	"github.com/chainreactors/fingers/ehole"
	"github.com/chainreactors/fingers/fingerprinthub"
	"github.com/chainreactors/fingers/fingers"
	"github.com/chainreactors/fingers/goby"
	wappalyzer "github.com/chainreactors/fingers/wappalyzer"
	"github.com/chainreactors/logs"
	"net/http"
	"strings"
)

func NewEngine() (*Engine, error) {
	engine := &Engine{
		Favicons: common.NewFavicons(),
	}
	var err error
	engine.FingersEngine, err = fingers.NewFingersEngine(fingers.HTTPFingerData, fingers.SocketFingerData)
	if err != nil {
		return nil, err
	}

	engine.FingerPrintEngine, err = fingerprinthub.NewFingerPrintHubEngine()
	if err != nil {
		return nil, err
	}

	engine.WappalyzerEngine, err = wappalyzer.NewWappalyzeEngine()
	if err != nil {
		return nil, err
	}

	engine.EHoleEngine, err = ehole.NewEHoleEngine()
	if err != nil {
		return nil, err
	}

	engine.GobyEngine, err = goby.NewGobyEngine()
	if err != nil {
		return nil, err
	}
	err = engine.Compile()
	if err != nil {
		return nil, err
	}
	return engine, nil
}

type Engine struct {
	FingersEngine     *fingers.FingersEngine                // support http/socket
	FingerPrintEngine *fingerprinthub.FingerPrintHubsEngine // support http
	WappalyzerEngine  *wappalyzer.Wappalyze                 // support http
	EHoleEngine       *ehole.EHoleEngine                    // support http
	GobyEngine        *goby.GobyEngine                      // support http
	*common.Favicons
}

func (engine *Engine) Compile() error {
	engine.Favicons = engine.FingersEngine.Favicons
	for hash, name := range engine.FingerPrintEngine.FaviconMap {
		engine.Favicons.Mmh3Fingers[hash] = name
	}
	for hash, name := range engine.EHoleEngine.FaviconMap {
		engine.Favicons.Mmh3Fingers[hash] = name
	}
	return nil
}

func (engine *Engine) DetectResponse(resp *http.Response) (common.Frameworks, error) {
	var raw bytes.Buffer

	content := common.ReadRaw(resp)
	header, body, _ := common.SplitContent(content)

	frames := make(common.Frameworks)
	if engine.FingersEngine != nil {
		var cert string
		if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
			cert = strings.Join(resp.TLS.PeerCertificates[0].DNSNames, ",")
		}
		fs, _ := engine.FingersEngine.HTTPMatch(raw.Bytes(), cert)
		frames.Merge(fs)
	}

	if engine.FingerPrintEngine != nil {
		fs := engine.FingerPrintEngine.Match(resp.Header, string(body))
		frames.Merge(fs)
	}

	if engine.WappalyzerEngine != nil {
		fs := engine.WappalyzerEngine.Fingerprint(resp.Header, body)
		frames.Merge(fs)
	}

	if engine.EHoleEngine != nil {
		fs := engine.EHoleEngine.Match(string(header), string(body))
		frames.Merge(fs)
	}

	if engine.GobyEngine != nil {
		fs := engine.GobyEngine.Match(string(body))
		frames.Merge(fs)
	}

	return frames, nil
}

func (engine *Engine) DetectContent(content []byte) (common.Frameworks, error) {
	frames := make(common.Frameworks)

	if engine.FingersEngine != nil {
		fs, _ := engine.FingersEngine.HTTPMatch(content, "")
		frames.Merge(fs)
	}

	resp, err := common.ParseContent(content)
	if err != nil {
		logs.Log.Error("not http response, " + err.Error())
		return nil, err
	}
	header, body, _ := common.SplitContent(content)
	if engine.FingerPrintEngine != nil {

		fs := engine.FingerPrintEngine.Match(resp.Header, string(body))
		frames.Merge(fs)
	}

	if engine.WappalyzerEngine != nil {
		fs := engine.WappalyzerEngine.Fingerprint(resp.Header, body)
		frames.Merge(fs)
	}

	if engine.EHoleEngine != nil {
		fs := engine.EHoleEngine.Match(string(header), string(body))
		frames.Merge(fs)
	}

	if engine.GobyEngine != nil {
		fs := engine.GobyEngine.Match(string(body))
		frames.Merge(fs)
	}

	return frames, nil
}
