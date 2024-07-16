package fingers

import (
	"fmt"
	"github.com/chainreactors/fingers/alias"
	"github.com/chainreactors/fingers/common"
	"github.com/chainreactors/fingers/ehole"
	"github.com/chainreactors/fingers/favicon"
	"github.com/chainreactors/fingers/fingerprinthub"
	"github.com/chainreactors/fingers/fingers"
	"github.com/chainreactors/fingers/goby"
	"github.com/chainreactors/fingers/resources"
	wappalyzer "github.com/chainreactors/fingers/wappalyzer"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/utils/httputils"
	"github.com/pkg/errors"
	"net/http"
	"strings"
)

const (
	FaviconEngine     = "favicon"
	FingersEngine     = "fingers"
	FingerPrintEngine = "fingerprinthub"
	WappalyzerEngine  = "wappalyzer"
	EHoleEngine       = "ehole"
	GobyEngine        = "goby"
)

var (
	AllEngines           = []string{FingersEngine, FingerPrintEngine, WappalyzerEngine, EHoleEngine, GobyEngine, FaviconEngine}
	DefaultEnableEngines = AllEngines

	NotFoundEngine = errors.New("engine not found")
)

func NewEngineWithCustomResource(portData, aliasData []byte, engines ...string) (*Engine, error) {
	if aliasData != nil {
		resources.AliasesData = aliasData
	}
	if portData != nil {
		resources.PortData = portData
	}
	return NewEngine(engines...)
}

func NewEngine(engines ...string) (*Engine, error) {
	if engines == nil {
		engines = DefaultEnableEngines
	}
	engine := &Engine{
		EnginesImpl: make(map[string]EngineImpl),
		//FaviconsEngine: favicon.NewFavicons(),
		Enabled: make(map[string]bool),
	}
	var err error
	engine.Aliases, err = alias.NewAliases()
	if err != nil {
		return nil, err
	}

	for _, name := range engines {
		err = engine.Enable(name)
		if err != nil {
			return nil, err
		}
	}

	err = engine.Compile()
	if err != nil {
		return nil, err
	}
	return engine, nil
}

type EngineImpl interface {
	Name() string
	Compile() error
	Len() int
	Match(content []byte) common.Frameworks
}

type Engine struct {
	EnginesImpl map[string]EngineImpl
	Aliases     *alias.Aliases
	Enabled     map[string]bool
}

func (engine *Engine) String() string {
	var s strings.Builder
	for name, impl := range engine.EnginesImpl {
		s.WriteString(fmt.Sprintf(" %s:%d", name, impl.Len()))
	}
	return strings.TrimSpace(s.String())
}

func (engine *Engine) Compile() error {
	if impl := engine.Fingers(); impl != nil {
		for hash, name := range impl.Favicons.Md5Fingers {
			engine.Favicon().Md5Fingers[hash] = name
		}
		for hash, name := range impl.Favicons.Mmh3Fingers {
			engine.Favicon().Mmh3Fingers[hash] = name
		}
	}

	if impl := engine.FingerPrintHub(); impl != nil {
		for hash, name := range impl.FaviconMap {
			engine.Favicon().Md5Fingers[hash] = name
		}
	}

	if impl := engine.EHole(); impl != nil {
		for hash, name := range impl.FaviconMap {
			engine.Favicon().Mmh3Fingers[hash] = name
		}
	}
	return nil
}

func (engine *Engine) Register(impl EngineImpl) bool {
	if impl == nil {
		return false
	}
	engine.EnginesImpl[impl.Name()] = impl
	engine.Enabled[impl.Name()] = true
	return true
}

func (engine *Engine) Enable(name string) error {
	var err error
	var impl EngineImpl
	if _, ok := engine.EnginesImpl[name]; !ok {
		switch name {
		case FingersEngine:
			impl, err = fingers.NewFingersEngine()
		case FingerPrintEngine:
			impl, err = fingerprinthub.NewFingerPrintHubEngine()
		case WappalyzerEngine:
			impl, err = wappalyzer.NewWappalyzeEngine()
		case EHoleEngine:
			impl, err = ehole.NewEHoleEngine()
		case GobyEngine:
			impl, err = goby.NewGobyEngine()
		case FaviconEngine:
			impl = favicon.NewFavicons()
		default:
			return NotFoundEngine
		}
		if err != nil {
			return err
		}
		engine.Register(impl)
	}

	engine.Enabled[name] = true
	return nil
}

func (engine *Engine) Disable(name string) {
	engine.Enabled[name] = false
}

func (engine *Engine) Fingers() *fingers.FingersEngine {
	if impl, ok := engine.EnginesImpl[FingersEngine]; ok {
		return impl.(*fingers.FingersEngine)
	}
	return nil
}

func (engine *Engine) Favicon() *favicon.FaviconsEngine {
	if impl, ok := engine.EnginesImpl[FaviconEngine]; ok {
		return impl.(*favicon.FaviconsEngine)
	}
	return nil
}

func (engine *Engine) FingerPrintHub() *fingerprinthub.FingerPrintHubsEngine {
	if impl, ok := engine.EnginesImpl[FingerPrintEngine]; ok {
		return impl.(*fingerprinthub.FingerPrintHubsEngine)
	}
	return nil
}

func (engine *Engine) Wappalyzer() *wappalyzer.Wappalyze {
	if impl, ok := engine.EnginesImpl[WappalyzerEngine]; ok {
		return impl.(*wappalyzer.Wappalyze)
	}
	return nil
}

func (engine *Engine) EHole() *ehole.EHoleEngine {
	if impl, ok := engine.EnginesImpl[EHoleEngine]; ok {
		return impl.(*ehole.EHoleEngine)
	}
	return nil
}

func (engine *Engine) Goby() *goby.GobyEngine {
	if impl, ok := engine.EnginesImpl[GobyEngine]; ok {
		return impl.(*goby.GobyEngine)
	}
	return nil
}

func (engine *Engine) GetEngine(name string) EngineImpl {
	if enabled, _ := engine.Enabled[name]; enabled {
		return engine.EnginesImpl[name]
	}
	return nil
}

func (engine *Engine) Match(resp *http.Response) common.Frameworks {
	content := httputils.ReadRaw(resp)
	body, header, _ := httputils.SplitHttpRaw(content)
	combined := make(common.Frameworks)
	for name, ok := range engine.Enabled {
		if !ok {
			continue
		}
		if engine.EnginesImpl[name] == nil {
			continue
		}
		var fs common.Frameworks
		switch name {
		case FingersEngine:
			var cert string
			if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
				cert = strings.Join(resp.TLS.PeerCertificates[0].DNSNames, ",")
			}
			fs, _ = engine.Fingers().HTTPMatch(content, cert)
		case WappalyzerEngine:
			fs = engine.Wappalyzer().Fingerprint(resp.Header, body)
		case FingerPrintEngine:
			fs = engine.FingerPrintHub().MatchWithHttpAndBody(resp.Header, string(body))
		case EHoleEngine:
			fs = engine.EHole().MatchWithHeaderAndBody(string(header), string(body))
		case GobyEngine:
			fs = engine.Goby().Match(content)
		default:
			if eng := engine.GetEngine(name); eng != nil {
				fs = eng.Match(content)
			} else {
				continue
			}
		}

		for _, frame := range fs {
			aliasFrame, ok := engine.Aliases.FindFramework(frame)
			if ok {
				frame.Name = aliasFrame.Name
				frame.UpdateAttributes(aliasFrame.ToWFN())
			}
			combined.Add(frame)
		}
	}
	return combined
}

func (engine *Engine) DetectResponse(resp *http.Response) (common.Frameworks, error) {
	return engine.Match(resp), nil
}

func (engine *Engine) DetectContent(content []byte) (common.Frameworks, error) {
	resp := httputils.NewResponseWithRaw(content)
	if resp == nil {
		logs.Log.Error("invalid http response")
		return nil, errors.New("invalid http response")
	}
	return engine.Match(resp), nil
}
