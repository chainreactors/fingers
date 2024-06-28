package fingers

import (
	"fmt"
	"github.com/chainreactors/fingers/common"
	"github.com/chainreactors/fingers/ehole"
	"github.com/chainreactors/fingers/fingerprinthub"
	"github.com/chainreactors/fingers/goby"
	"net/http"
	"testing"
)

func TestNewEngine(t *testing.T) {
	engine, err := NewEngine()
	if err != nil {
		panic(err)
	}
	resp, err := http.Get("http://81.70.40.138/github.html")
	if err != nil {
		return
	}
	frames, err := engine.DetectResponse(resp)
	if err != nil {
		return
	}
	fmt.Println(frames)
}

func TestFingerPrintHubsEngine(t *testing.T) {
	engine, err := fingerprinthub.NewFingerPrintHubEngine()
	if err != nil {
		t.Error(err)
	}
	resp, err := http.Get("http://81.70.40.138/github.html")
	if err != nil {
		return
	}

	content := common.ReadRaw(resp)
	_, body, ok := common.SplitContent(content)
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
	resp, err := http.Get("http://81.70.40.138/github.html")
	if err != nil {
		return
	}

	content := common.ReadRaw(resp)
	header, body, ok := common.SplitContent(content)
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
	resp, err := http.Get("http://81.70.40.138/github.html")
	if err != nil {
		return
	}

	content := common.ReadRaw(resp)
	frames := engine.Match(string(content))
	fmt.Println(frames)
}
