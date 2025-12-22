package gonmap

import (
	"compress/gzip"
	"encoding/json"
	"strings"
)

// loadServicesFromBytes 从bytes加载services数据
func (n *Nmap) loadServicesFromBytes(servicesData []byte) {
	// 从bytes加载nmap-services.json.gz
	reader, err := gzip.NewReader(strings.NewReader(string(servicesData)))
	if err != nil {
		return // 忽略错误，使用默认值
	}
	defer reader.Close()

	// 解析JSON数据
	decoder := json.NewDecoder(reader)
	var data ServicesData
	err = decoder.Decode(&data)
	if err != nil {
		return // 忽略错误，使用默认值
	}

	// 保存数据
	n.servicesData = &data

	// 构建nmapServices数组以保持兼容性
	n.nmapServices = n.buildNmapServicesArray(&data)
}

// loadProbesFromBytes 从bytes加载probes数据
func (n *Nmap) loadProbesFromBytes(probesData []byte) {
	// 从bytes加载压缩的nmap数据
	reader, err := gzip.NewReader(strings.NewReader(string(probesData)))
	if err != nil {
		return
	}
	defer reader.Close()

	// 创建JSON解码器
	decoder := json.NewDecoder(reader)
	var data NmapProbesData

	// 解码JSON数据
	err = decoder.Decode(&data)
	if err != nil {
		return
	}

	// 加载探针数据并重新编译正则表达式
	for _, probe := range data.Probes {
		// 重新编译每个Match中的正则表达式
		for _, match := range probe.MatchGroup {
			// 重新编译PatternRegexp，从JSON反序列化时不会保存正则对象
			match.PatternRegexp = match.getPatternRegexp(match.Pattern, "")
		}
		n.pushProbe(*probe)
	}
}

// addCustomMatches 添加自定义指纹
func (n *Nmap) addCustomMatches() {
	//新增自定义指纹信息
	n.AddMatch("TCP_GetRequest", `echo m|^GET / HTTP/1.0\r\n\r\n$|s`)
	n.AddMatch("TCP_GetRequest", `mongodb m|.*It looks like you are trying to access MongoDB.*|s p/MongoDB/`)
	n.AddMatch("TCP_GetRequest", `http m|^HTTP/1\.[01] \d\d\d (?:[^\r\n]+\r\n)*?Server: ([^\r\n]+)| p/$1/`)
	n.AddMatch("TCP_GetRequest", `http m|^HTTP/1\.[01] \d\d\d|`)
	n.AddMatch("TCP_NULL", `mysql m|.\x00\x00..j\x04Host '.*' is not allowed to connect to this MariaDB server| p/MariaDB/`)
	n.AddMatch("TCP_NULL", `mysql m|.\x00\x00\x00\x0a([\d.]+)\x00.*MariaDB| p/MariaDB/ v/$1/`)
	n.AddMatch("TCP_NULL", `mysql m|.\x00\x00\x00\x0a([\d.]+)\x00| p/MySQL/ v/$1/`)
}

// optimizeProbes 优化探针配置
func (n *Nmap) optimizeProbes() {
	// HTTP端口优化
	httpPorts := []int{80, 443, 8080, 8443, 8000, 8888, 9090}
	for _, port := range httpPorts {
		if port < len(n.portProbeMap) {
			// 将HTTP探针放在前面
			n.portProbeMap[port] = append([]string{"TCP_GetRequest"}, n.portProbeMap[port]...)
		}
	}

	// SSL端口优化
	sslPorts := []int{443, 8443, 3389}
	for _, port := range sslPorts {
		if port < len(n.portProbeMap) {
			// 将SSL探针放在前面
			for _, sslProbe := range n.sslProbeMap {
				n.portProbeMap[port] = append([]string{sslProbe}, n.portProbeMap[port]...)
			}
		}
	}
}
