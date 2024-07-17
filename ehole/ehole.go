package ehole

import (
	"bytes"
	"github.com/chainreactors/fingers/common"
	"github.com/chainreactors/fingers/resources"
	"github.com/chainreactors/utils/httputils"
	"regexp"
	"strings"
)

const (
	KeywordMethod = "keyword"
	RegularMethod = "regular"
	FaviconMethod = "faviconhash"
)

const (
	BodyLocation   = "body"
	HeaderLocation = "header"
	TitleLocation  = "title"
)

func NewEHoleEngine() (*EHoleEngine, error) {
	var engine *EHoleEngine
	err := resources.UnmarshalData(resources.EholeData, &engine)
	if err != nil {
		return nil, err
	}
	err = engine.Compile()
	if err != nil {
		return nil, err
	}
	return engine, nil
}

type EHoleEngine struct {
	Fingerprints []*Fingerprint `json:"fingerprint"`
	FaviconMap   map[string]string
}

func (engine *EHoleEngine) Name() string {
	return "ehole"
}

func (engine *EHoleEngine) Len() int {
	return len(engine.Fingerprints)
}

func (engine *EHoleEngine) Compile() error {
	engine.FaviconMap = make(map[string]string)
	for _, finger := range engine.Fingerprints {
		if finger.Method == RegularMethod {
			finger.compiledRegexp = make([]*regexp.Regexp, len(finger.Keyword))
			for _, reg := range finger.Keyword {
				finger.compiledRegexp = append(finger.compiledRegexp, regexp.MustCompile(reg))
			}
		} else if finger.Method == KeywordMethod {
			finger.lowerKeyword = make([]string, len(finger.Keyword))
			for _, word := range finger.Keyword {
				finger.lowerKeyword = append(finger.lowerKeyword, strings.ToLower(word))
			}
		} else if finger.Method == FaviconMethod {
			for _, hash := range finger.Keyword {
				engine.FaviconMap[hash] = finger.Cms
			}
		}
	}
	return nil
}

func (engine *EHoleEngine) Match(content []byte) common.Frameworks {
	var header, body string
	content = bytes.ToLower(content)
	bodyBytes, headerBytes, ok := httputils.SplitHttpRaw(content)
	if ok {
		header = string(headerBytes)
		body = string(bodyBytes)
		return engine.MatchWithHeaderAndBody(header, body)
	}
	return make(common.Frameworks)
}

func (engine *EHoleEngine) MatchWithHeaderAndBody(header, body string) common.Frameworks {
	frames := make(common.Frameworks)
	for _, finger := range engine.Fingerprints {
		frame := finger.Match(header, body)
		if frame != nil {
			frames.Add(frame)
		}
	}
	return frames
}

type Fingerprint struct {
	Cms            string   `json:"cms"`
	Method         string   `json:"method"`
	Location       string   `json:"location"`
	Keyword        []string `json:"keyword"`
	lowerKeyword   []string `json:"-"`
	compiledRegexp []*regexp.Regexp
}

func (finger *Fingerprint) Match(header, body string) *common.Framework {
	switch finger.Location {
	case BodyLocation, TitleLocation:
		if finger.MatchMethod(body) {
			return common.NewFramework(finger.Cms, common.FrameFromEhole)
		}
	case HeaderLocation:
		if finger.MatchMethod(header) {
			return common.NewFramework(finger.Cms, common.FrameFromEhole)
		}
	default:
		return nil
	}
	return nil
}

func (finger *Fingerprint) MatchMethod(content string) bool {
	switch finger.Method {
	case KeywordMethod:
		return finger.MatchKeyword(content)
	case RegularMethod:
		return finger.MatchRegexp(content)
	default:
		return false
	}
}

func (finger *Fingerprint) MatchKeyword(content string) bool {
	for _, k := range finger.Keyword {
		if !strings.Contains(content, k) {
			return false
		}
	}
	return true
}

func (finger *Fingerprint) MatchRegexp(content string) bool {
	for _, reg := range finger.compiledRegexp {
		if !reg.Match([]byte(content)) {
			return false
		}
	}
	return true
}
