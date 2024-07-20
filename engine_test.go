package fingers

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"github.com/chainreactors/fingers/ehole"
	"github.com/chainreactors/fingers/fingerprinthub"
	"github.com/chainreactors/fingers/fingers"
	"github.com/chainreactors/fingers/goby"
	"github.com/chainreactors/fingers/wappalyzer"
	"github.com/chainreactors/utils/httputils"
	"net/http"
	"testing"
	"time"
)

func TestEngine(t *testing.T) {
	engine, err := NewEngine()
	if err != nil {
		panic(err)
	}
	fmt.Println(engine.String())

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := client.Get("http://127.0.0.1:8089")
	if err != nil {
		panic(err)
	}
	start := time.Now()
	content := httputils.ReadRaw(resp)
	frames, err := engine.DetectContent(content)
	if err != nil {
		return
	}
	println("耗时: " + time.Since(start).String())
	fmt.Println(frames.String())
	for _, f := range frames {
		fmt.Println("cpe: ", f.CPE(), "||||", f.String())
	}
}

func TestEngine_Match(t *testing.T) {
	engine, err := NewEngine()
	if err != nil {
		panic(err)
	}
	resp, err := http.Get("http://127.0.0.1:8089")
	if err != nil {
		panic(err)
	}
	frames := engine.Match(resp)
	fmt.Println(frames.String())
}

func TestFavicon(t *testing.T) {
	engine, err := NewEngine()
	if err != nil {
		panic(err)
	}
	resp, err := http.Get("http://baidu.com/favicon.ico")
	if err != nil {
		return
	}
	content := httputils.ReadRaw(resp)
	body, _, _ := httputils.SplitHttpRaw(content)
	frame := engine.DetectFavicon(body)
	fmt.Println(frame)
}

func TestFingersEngine(t *testing.T) {
	engine, err := fingers.NewFingersEngine()
	if err != nil {
		t.Error(err)
	}
	resp, err := http.Get("http://127.0.0.1")
	if err != nil {
		return
	}

	content := httputils.ReadRaw(resp)
	frames := engine.Match(content)
	for _, frame := range frames {
		t.Log(frame)
	}
}

func TestEngine_MatchWithEngines(t *testing.T) {
	engine, err := NewEngine()
	if err != nil {
		t.Error(err)
	}
	resp, err := http.Get("http://127.0.0.1")
	if err != nil {
		return
	}

	need := []string{FingersEngine, FingerPrintEngine}
	frames := engine.MatchWithEngines(resp, need...)
	for _, frame := range frames {
		t.Log(frame)
	}
}

func TestFingerPrintHubsEngine(t *testing.T) {
	engine, err := fingerprinthub.NewFingerPrintHubEngine()
	if err != nil {
		t.Error(err)
	}
	resp, err := http.Get("http://127.0.0.1")
	if err != nil {
		return
	}

	content := httputils.ReadRaw(resp)
	_, body, ok := httputils.SplitHttpRaw(content)
	if ok {
		frames := engine.MatchWithHttpAndBody(resp.Header, string(body))
		for _, frame := range frames {
			t.Log(frame)
		}
	}
}

func TestEHoleEngine(t *testing.T) {
	engine, err := ehole.NewEHoleEngine()
	if err != nil {
		t.Error(err)
	}
	resp, err := http.Get("http://127.0.0.1:8089")
	if err != nil {
		return
	}

	content := httputils.ReadRaw(resp)
	header, body, ok := httputils.SplitHttpRaw(content)
	if ok {
		frames := engine.MatchWithHeaderAndBody(string(header), string(body))
		for _, frame := range frames {
			t.Log(frame)
		}
	}
}

func TestGobyEngine(t *testing.T) {
	engine, err := goby.NewGobyEngine()
	if err != nil {
		t.Error(err)
	}
	resp, err := http.Get("http://127.0.0.1:8000")
	if err != nil {
		return
	}

	content := httputils.ReadRaw(resp)
	content = bytes.ToLower(content)
	start := time.Now()
	frames := engine.Match(content)
	fmt.Println(frames)
	fmt.Println(time.Since(start).String())
}

func TestEngine_Wappalyzer(t *testing.T) {
	engine, err := wappalyzer.NewWappalyzeEngine()
	if err != nil {
		t.Error(err)
		return
	}
	resp, err := http.Get("http://127.0.0.1:8000")
	if err != nil {
		return
	}

	content := httputils.ReadBody(resp)
	start := time.Now()
	frames := engine.Fingerprint(resp.Header, content)
	fmt.Println(frames)
	fmt.Println(time.Since(start).String())
}

func TestAlias(t *testing.T) {
	engine, err := NewEngine()
	if err != nil {
		t.Error()
		return
	}
	fmt.Println(engine.FindAny("cdncache_server"))
	fmt.Println(engine.Aliases.Aliases["cdn-cache-server"])
	fmt.Println(engine.Aliases.Map["fingers"]["cdn-cache-server"])
}
