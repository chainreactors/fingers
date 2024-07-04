package fingers

import (
	"crypto/tls"
	"fmt"
	"github.com/chainreactors/fingers/ehole"
	"github.com/chainreactors/fingers/fingerprinthub"
	"github.com/chainreactors/fingers/goby"
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
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Get("https://81.70.40.17:443/home.php")
	if err != nil {
		panic(err)
	}
	start := time.Now()
	frames, err := engine.DetectResponse(resp)
	if err != nil {
		return
	}
	println(time.Since(start).String())
	fmt.Println(frames.String())
	for _, f := range frames {
		fmt.Println("cpe: ", f.CPE(), "||||", f.String())
	}
}

func TestFavicon(t *testing.T) {
	engine, err := NewEngine()
	if err != nil {
		panic(err)
	}
	resp, err := http.Get("http://81.70.40.202:8080/favicon.ico")
	if err != nil {
		return
	}
	content := httputils.ReadRaw(resp)
	_, body, _ := httputils.SplitHttpRaw(content)
	frames := engine.HashContentMatch(body)
	fmt.Println(frames)
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
		frames := engine.Match(resp.Header, string(body))
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
	resp, err := http.Get("http://127.0.0.1")
	if err != nil {
		return
	}

	content := httputils.ReadRaw(resp)
	header, body, ok := httputils.SplitHttpRaw(content)
	if ok {
		frames := engine.Match(string(header), string(body))
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
	resp, err := http.Get("http://127.0.0.1")
	if err != nil {
		return
	}

	content := httputils.ReadRaw(resp)
	frames := engine.Match(string(content))
	fmt.Println(frames)
}
