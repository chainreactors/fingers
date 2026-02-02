package fingers

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/chainreactors/fingers/common"
	"github.com/chainreactors/fingers/ehole"
	"github.com/chainreactors/fingers/fingerprinthub"
	"github.com/chainreactors/fingers/fingers"
	"github.com/chainreactors/fingers/goby"
	"github.com/chainreactors/fingers/resources"
	"github.com/chainreactors/fingers/wappalyzer"
	"github.com/chainreactors/utils/httputils"
)

func TestEngine(t *testing.T) {
	// 在检测 `DetectContent` 前进行内存分析

	// Your test code
	engine, err := NewEngine()
	if err != nil {
		panic(err)
	}
	fmt.Println(engine.String())

	//client := &http.Client{
	//	Transport: &http.Transport{
	//		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	//	},
	//}
	//resp, err := client.Get("https://boce.aliyun.com/detect/http")
	//if err != nil {
	//	panic(err)
	//}
	//start := time.Now()
	//content := httputils.ReadRaw(resp)

	// 调用 DetectContent

	content, err := os.ReadFile("1.raw")
	if err != nil {
		return
	}
	frames, err := engine.DetectContent(content)
	if err != nil {
		return
	}

	// 打印执行时间
	//println("耗时: " + time.Since(start).String())
	fmt.Println(frames.String())

	// 打印内存分配
	for _, f := range frames {
		fmt.Println("cpe: ", f.CPE(), "||||", f.String())
	}
}

func TestEngine_Match(t *testing.T) {
	engine, err := NewEngine()
	if err != nil {
		panic(err)
	}
	resp, err := http.Get("http://nc.scsstjt.com:8090/index.jsp")
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
	engine, err := fingers.NewFingersEngine(resources.FingersHTTPData, resources.FingersSocketData, resources.PortData)
	if err != nil {
		t.Error(err)
		return
	}

	// 模拟比较真实的浏览器请求头
	headers := http.Header{
		"User-Agent": []string{
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
		},
		"Accept": []string{
			"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
		},
		"Accept-Language": []string{"zh-CN,zh;q=0.9,en;q=0.8"},
		"Accept-Encoding": []string{"gzip, deflate"},
		"Connection":      []string{"keep-alive"},
		// 如果目标网站有严格的 referer 检查，可以加上
		// "Referer": []string{"https://www.google.com/"},
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	req, err := http.NewRequest("GET", "http://nc.scsstjt.com:8090/login/login.php", nil)
	if err != nil {
		t.Fatal(err)
	}

	// 一次性设置所有 header
	req.Header = headers

	resp, err := client.Do(req)
	if err != nil {
		t.Log(err)
		return
	}
	defer resp.Body.Close()

	content := httputils.ReadRaw(resp)
	frames := engine.WebMatch(content)

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
	engine, err := fingerprinthub.NewFingerPrintHubEngine(resources.FingerprinthubWebData, resources.FingerprinthubServiceData)
	if err != nil {
		t.Error(err)
	}
	resp, err := http.Get("http://127.0.0.1")
	if err != nil {
		return
	}

	content := httputils.ReadRaw(resp)
	frames := engine.WebMatch(content)
	for _, frame := range frames {
		t.Log(frame)
	}
}

func TestEHoleEngine(t *testing.T) {
	engine, err := ehole.NewEHoleEngine(resources.EholeData)
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
	engine, err := goby.NewGobyEngine(resources.GobyData)
	if err != nil {
		t.Error(err)
	}
	resp, err := http.Get("https://baidu.com")
	if err != nil {
		return
	}

	content := httputils.ReadRaw(resp)
	content = bytes.ToLower(content)
	start := time.Now()
	frames := engine.WebMatch(content)
	fmt.Println(frames)
	fmt.Println(time.Since(start).String())
}

func TestEngine_Wappalyzer(t *testing.T) {
	engine, err := wappalyzer.NewWappalyzeEngine(resources.WappalyzerData)
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

func TestNmapEngine(t *testing.T) {
	engine, err := NewEngine(NmapEngine)
	if err != nil {
		t.Error(err)
		return
	}

	nmapEngine := engine.Nmap()
	if nmapEngine == nil {
		t.Error("nmap engine not found")
		return
	}

	fmt.Printf("nmap engine loaded with %d fingerprints\n", nmapEngine.Len())

	// 测试Service指纹匹配 - 使用common包的默认实现
	testServiceSender := common.NewServiceSender(3 * time.Second)

	testServiceCallback := func(result *common.ServiceResult) {
		if result.Framework != nil {
			t.Logf("detected service: %s", result.Framework.String())
		}
	}

	result := nmapEngine.ServiceMatch("127.0.0.1", "80", 1, testServiceSender, testServiceCallback)
	if result != nil && result.Framework != nil {
		t.Logf("service result: %s", result.Framework.String())
	}

	// 测试引擎能力
	capability := nmapEngine.Capability()
	if !capability.SupportService {
		t.Error("nmap engine should support service fingerprinting")
	}
	if capability.SupportWeb {
		t.Error("nmap engine should not support web fingerprinting")
	}

	// 测试WebMatch应该返回空结果
	webFrames := nmapEngine.WebMatch([]byte("test"))
	if len(webFrames) != 0 {
		t.Error("nmap engine WebMatch should return empty results")
	}
}

// TestServiceEngine 测试Service引擎的能力
func TestServiceEngine(t *testing.T) {
	engine, err := NewEngine(NmapEngine)
	if err != nil {
		t.Error(err)
		return
	}

	// 测试获取支持Service的引擎
	serviceEngines := engine.GetEnginesByType(common.ServiceFingerprint)
	expectedServiceEngines := []string{NmapEngine}

	if len(serviceEngines) != len(expectedServiceEngines) {
		t.Errorf("Expected %d service engines, got %d", len(expectedServiceEngines), len(serviceEngines))
	}

	for _, expected := range expectedServiceEngines {
		found := false
		for _, actual := range serviceEngines {
			if actual == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected service engine %s not found", expected)
		}
	}

	// 测试DetectService API
	testSender := common.NewServiceSender(3 * time.Second)

	ports := []int{80, 443, 445, 135, 1080, 3306, 1433, 1521}
	for _, port := range ports {
		results, err := engine.DetectService("127.0.0.1", strconv.Itoa(port), 9, testSender, nil)
		if err != nil {
			t.Logf("DetectService error: %v", err)
		}
		if len(results) > 0 && results[0].Framework != nil {
			fmt.Printf("DetectService result: %s\n", results[0].Framework.String())
		}
	}
}
