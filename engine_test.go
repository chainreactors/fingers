package fingers

import (
	"fmt"
	"github.com/chainreactors/fingers/common"
	"github.com/chainreactors/fingers/ehole"
	"github.com/chainreactors/fingers/fingerprinthub"
	"net/http"
	"testing"
)

func TestNewEngine(t *testing.T) {
	engine, err := NewEngine()
	if err != nil {
		panic(err)
	}
	resp, err := http.Get("http://81.70.40.138")
	if err != nil {
		return
	}
	frames, err := engine.DetectResponse(resp)
	if err != nil {
		return
	}
	fmt.Println(frames)
}

func TestFingerPrintHubsEngine_Match(t *testing.T) {
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

func TestEHoleEngine_Match(t *testing.T) {
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
