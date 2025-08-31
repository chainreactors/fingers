package gonmap

import (
	"strings"
)

type Nmap struct {
	exclude      PortList
	probeNameMap map[string]*Probe

	// 按稀有度分组的探针映射 map[Rarity][]*Probe
	rarityProbeMap map[int][]*Probe
	portProbeMap   map[int]ProbeList
	//bypassAllProbePort PortList
	sslSecondProbeMap ProbeList
	sslProbeMap       ProbeList
}

func (n *Nmap) Scan(ip string, port int, level int, sender func(host string, port int, data []byte, tls bool) ([]byte, bool, error)) (status Status, response *Response) {
	// 为本次扫描创建独立的已使用探针列表
	localProbeUsed := make(ProbeList, 0)

	// 根据稀有度从低到高选择探针
	var probeNames ProbeList
	for rarity := 1; rarity <= level; rarity++ {
		if probes, exists := n.rarityProbeMap[rarity]; exists {
			for _, probe := range probes {
				probeNames = append(probeNames, probe.Name)
			}
		}
	}

	// 添加端口相关探针
	probeNames = append(probeNames, n.portProbeMap[port]...)
	probeNames = append(probeNames, n.sslProbeMap...)

	//探针去重
	probeNames = probeNames.removeDuplicate()

	if len(probeNames) == 0 {
		return NotMatched, nil
	}

	// 首先尝试第一个探针
	firstProbe := probeNames[0]
	status, response = n.getResponseByProbes(ip, port, level, sender, &localProbeUsed, firstProbe)
	if status == Closed || status == Matched {
		return status, response
	}

	// 如果第一个探针没有匹配，尝试其他探针
	otherProbes := probeNames[1:]
	return n.getResponseByProbes(ip, port, level, sender, &localProbeUsed, otherProbes...)
}

// getResponseByProbes 使用外部sender和本地probeUsed进行扫描
func (n *Nmap) getResponseByProbes(host string, port int, level int, sender func(host string, port int, data []byte, tls bool) ([]byte, bool, error), localProbeUsed *ProbeList, probes ...string) (status Status, response *Response) {
	var responseNotMatch *Response
	for _, requestName := range probes {
		if localProbeUsed.exist(requestName) {
			continue
		}
		*localProbeUsed = append(*localProbeUsed, requestName)
		p := n.probeNameMap[requestName]

		status, response = n.getResponse(host, port, p.SSLPorts.exist(port), sender, p)
		if status == Closed {
			return Closed, nil
		}
		if status == Matched {
			// 如果匹配到ssl，需要进行二次扫描
			if response.FingerPrint.Service == "ssl" {
				sslStatus, sslResponse := n.getSSLSecondProbes(host, port, level, sender, localProbeUsed)
				if sslStatus == Matched {
					return Matched, sslResponse
				}
			}
			return Matched, response
		}
		if status == Open {
			responseNotMatch = response
		}
	}

	if responseNotMatch != nil {
		response = responseNotMatch
	}
	return status, response
}

// getSSLSecondProbes SSL二次探测
func (n *Nmap) getSSLSecondProbes(host string, port int, level int, sender func(host string, port int, data []byte, tls bool) ([]byte, bool, error), localProbeUsed *ProbeList) (status Status, response *Response) {
	// 直接使用SSL二次探测的探针（不需要额外过滤，已在主扫描中过滤）
	status, response = n.getResponseByProbes(host, port, level, sender, localProbeUsed, n.sslSecondProbeMap...)
	if status != Matched || response.FingerPrint.Service == "ssl" {
		status, response = n.getResponseByHTTPS(host, port, sender)
	}
	if status == Matched && response.FingerPrint.Service != "ssl" {
		if response.FingerPrint.Service == "http" {
			response.FingerPrint.Service = "https"
		}
		return Matched, response
	}
	return NotMatched, response
}

// getResponseByHTTPS 处理HTTPS
func (n *Nmap) getResponseByHTTPS(host string, port int, sender func(host string, port int, data []byte, tls bool) ([]byte, bool, error)) (status Status, response *Response) {
	var httpRequest = n.probeNameMap["TCP_GetRequest"]
	return n.getResponse(host, port, true, sender, httpRequest)
}

// getResponse 使用外部sender进行网络通信的核心方法
func (n *Nmap) getResponse(host string, port int, tls bool, sender func(host string, port int, data []byte, tls bool) ([]byte, bool, error), p *Probe) (Status, *Response) {
	//if port == 53 {
	//	if DnsScan(host, port) {
	//		return Matched, &dnsResponse
	//	} else {
	//		return Closed, nil
	//	}
	//}

	// 使用外部sender发送探测数据
	probeData := []byte(p.buildRequest(host)) // 构建探测请求数据
	responseData, actualTLS, err := sender(host, port, probeData, tls)

	if err != nil {
		// 根据错误类型判断端口状态
		errStr := err.Error()
		if strings.Contains(errStr, "connection refused") ||
			strings.Contains(errStr, "no route to host") ||
			strings.Contains(errStr, "network is unreachable") {
			return Closed, nil
		}
		if p.Protocol == "UDP" && strings.Contains(errStr, "refused") {
			return Closed, nil
		}
		return Open, nil
	}

	response := &Response{
		Raw:         string(responseData),
		TLS:         actualTLS,
		FingerPrint: &FingerPrint{},
	}

	//若存在返回包，则开始捕获指纹
	fingerPrint := n.getFinger(string(responseData), actualTLS, p.Name)
	response.FingerPrint = fingerPrint

	if fingerPrint.Service == "" {
		return NotMatched, response
	} else {
		return Matched, response
	}
}

func (n *Nmap) getFinger(responseRaw string, tls bool, requestName string) *FingerPrint {
	data := n.convResponse(responseRaw)
	probe := n.probeNameMap[requestName]

	finger := probe.match(data)

	if tls == true {
		if finger.Service == "http" {
			finger.Service = "https"
		}
	}

	if finger.Service != "" || n.probeNameMap[requestName].Fallback == "" {
		//标记当前探针名称
		finger.ProbeName = requestName
		return finger
	}

	fallback := n.probeNameMap[requestName].Fallback
	fallbackProbe := n.probeNameMap[fallback]
	for fallback != "" {
		finger = fallbackProbe.match(data)
		fallback = n.probeNameMap[fallback].Fallback
		if finger.Service != "" {
			break
		}
	}
	//标记当前探针名称
	finger.ProbeName = requestName
	return finger
}

func (n *Nmap) convResponse(s1 string) string {
	//为了适配go语言的沙雕正则，只能讲二进制强行转换成UTF-8
	b1 := []byte(s1)
	var r1 []rune
	for _, i := range b1 {
		r1 = append(r1, rune(i))
	}
	s2 := string(r1)
	return s2
}

func (n *Nmap) AddMatch(probeName string, expr string) {
	var probe = n.probeNameMap[probeName]
	probe.loadMatch(expr, false)
}

//初始化类

func (n *Nmap) loads(s string) {
	lines := strings.Split(s, "\n")
	var probeGroups [][]string
	var probeLines []string
	for _, line := range lines {
		if !n.isCommand(line) {
			continue
		}
		commandName := line[:strings.Index(line, " ")]
		if commandName == "Exclude" {
			n.loadExclude(line)
			continue
		}
		if commandName == "Probe" {
			if len(probeLines) != 0 {
				probeGroups = append(probeGroups, probeLines)
				probeLines = []string{}
			}
		}
		probeLines = append(probeLines, line)
	}
	probeGroups = append(probeGroups, probeLines)

	for _, lines := range probeGroups {
		p := parseProbe(lines)
		n.pushProbe(*p)
	}
}

func (n *Nmap) loadExclude(expr string) {
	n.exclude = parsePortList(expr)
}

func (n *Nmap) pushProbe(p Probe) {
	n.probeNameMap[p.Name] = &p

	// 按稀有度分组探针
	n.rarityProbeMap[p.Rarity] = append(n.rarityProbeMap[p.Rarity], &p)

	//建立端口扫描对应表，将根据端口号决定使用何种请求包
	//0记录所有使用的探针
	n.portProbeMap[0] = append(n.portProbeMap[0], p.Name)

	//分别压入sslports,ports
	for _, i := range p.Ports {
		n.portProbeMap[i] = append(n.portProbeMap[i], p.Name)
	}

	for _, i := range p.SSLPorts {
		n.portProbeMap[i] = append(n.portProbeMap[i], p.Name)
	}
}

func (n *Nmap) fixFallback() {
	for probeName, probeType := range n.probeNameMap {
		fallback := probeType.Fallback
		if fallback == "" {
			continue
		}
		if _, ok := n.probeNameMap["TCP_"+fallback]; ok {
			n.probeNameMap[probeName].Fallback = "TCP_" + fallback
		} else {
			n.probeNameMap[probeName].Fallback = "UDP_" + fallback
		}
	}
}

func (n *Nmap) isCommand(line string) bool {
	//删除注释行和空行
	if len(line) < 2 {
		return false
	}
	if line[:1] == "#" {
		return false
	}
	//删除异常命令
	commandName := line[:strings.Index(line, " ")]
	commandArr := []string{
		"Exclude", "Probe", "match", "softmatch", "ports", "sslports", "totalwaitms", "tcpwrappedms", "rarity", "fallback",
	}
	for _, item := range commandArr {
		if item == commandName {
			return true
		}
	}
	return false
}

// 工具函数
//func DnsScan(host string, port int) bool {
//	domainServer := fmt.Sprintf("%s:%d", host, port)
//	c := dns.Client{
//		Timeout: 2 * time.Second,
//	}
//	m := dns.Msg{}
//	// 最终都会指向一个ip 也就是typeA, 这样就可以返回所有层的cname.
//	m.SetQuestion("www.baidu.com.", dns.TypeA)
//	_, _, err := c.Exchange(&m, domainServer)
//	if err != nil {
//		return false
//	}
//	return true
//}
