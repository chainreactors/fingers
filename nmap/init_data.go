package gonmap

import (
	"github.com/chainreactors/fingers/resources"
)

// loadServicesFromBytes 从bytes加载services数据（支持gzip压缩或未压缩的JSON格式）
func (n *Nmap) loadServicesFromBytes(servicesData []byte) {
	var data ServicesData
	if err := resources.UnmarshalData(servicesData, &data); err != nil {
		return // 忽略错误，使用默认值
	}

	// 保存数据
	n.servicesData = &data

	// 构建nmapServices数组以保持兼容性
	n.nmapServices = n.buildNmapServicesArray(&data)
}

// loadProbesFromBytes 从bytes加载probes数据（支持gzip压缩或未压缩的JSON格式）
func (n *Nmap) loadProbesFromBytes(probesData []byte) {
	var data NmapProbesData

	if err := resources.UnmarshalData(probesData, &data); err != nil {
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
	n.AddMatch("TCP_NULL", `mysql m|.\x00\x00..j\x04Host '.*' is not allowed to connect to this MySQL server| p/MySQL/`)
	n.AddMatch("TCP_NULL", `mysql m|.\x00\x00\x00\x0a(\d+\.\d+\.\d+)\x00.*caching_sha2_password\x00| p/MariaDB/ v/$1/`)
	n.AddMatch("TCP_NULL", `mysql m|.\x00\x00\x00\x0a(\d+\.\d+\.\d+)\x00.*caching_sha2_password\x00| p/MariaDB/ v/$1/`)
	n.AddMatch("TCP_NULL", `mysql m|.\x00\x00\x00\x0a([\d.-]+)-MariaDB\x00.*mysql_native_password\x00| p/MariaDB/ v/$1/`)
	n.AddMatch("TCP_NULL", `redis m|-DENIED Redis is running in.*| p/Redis/ i/Protected mode/`)
	n.AddMatch("TCP_NULL", `telnet m|^.*Welcome to visit (.*) series router!.*|s p/$1 Router/`)
	n.AddMatch("TCP_NULL", `telnet m|^Username: ??|`)
	n.AddMatch("TCP_NULL", `telnet m|^.*Telnet service is disabled or Your telnet session has expired due to inactivity.*|s i/Disabled/`)
	n.AddMatch("TCP_NULL", `telnet m|^.*Telnet connection from (.*) refused.*|s i/Refused/`)
	n.AddMatch("TCP_NULL", `telnet m|^.*Command line is locked now, please retry later.*\x0d\x0a\x0d\x0a|s i/Locked/`)
	n.AddMatch("TCP_NULL", `telnet m|^.*Warning: Telnet is not a secure protocol, and it is recommended to use Stelnet.*|s`)
	n.AddMatch("TCP_NULL", `telnet m|^telnetd:|s`)
	n.AddMatch("TCP_NULL", `telnet m|^.*Quopin CLI for (.*)\x0d\x0a\x0d\x0a|s p/$1/`)
	n.AddMatch("TCP_NULL", `telnet m|^\x0d\x0aHello, this is FRRouting \(version ([\d.]+)\).*|s p/FRRouting/ v/$1/`)
	n.AddMatch("TCP_NULL", `telnet m|^.*User Access Verification.*Username:|s`)
	n.AddMatch("TCP_NULL", `telnet m|^Connection failed.  Windows CE Telnet Service cannot accept anymore concurrent users.|s o/Windows/`)
	n.AddMatch("TCP_NULL", `telnet m|^\x0d\x0a\x0d\x0aWelcome to the host.\x0d\x0a.*|s o/Windows/`)
	n.AddMatch("TCP_NULL", `telnet m|^.*Welcome Visiting Huawei Home Gateway\x0d\x0aCopyright by Huawei Technologies Co., Ltd.*Login:|s p/Huawei/`)
	n.AddMatch("TCP_NULL", `telnet m|^..\x01..\x03..\x18..\x1f|s p/Huawei/`)
	n.AddMatch("TCP_NULL", `smtp m|^220 ([a-z0-1.-]+).*| h/$1/`)
	n.AddMatch("TCP_NULL", `ftp m|^220 H3C Small-FTP Server Version ([\d.]+).* | p/H3C Small-FTP/ v/$1/`)
	n.AddMatch("TCP_NULL", `ftp m|^421[- ]Service not available..*|`)
	n.AddMatch("TCP_NULL", `ftp m|^220[- ].*filezilla.*|i p/FileZilla/`)

	// Add DCERPC/MSRPC match for TCP_NULL probe - matches the bind_ack response
	n.AddMatch("TCP_NULL", `msrpc m|^\x05\x00\x0d\x03|s p/Microsoft Windows RPC/`)

	n.AddMatch("TCP_TerminalServerCookie", `ms-wbt-server m|^\x03\0\0\x13\x0e\xd0\0\0\x124\0\x02.*\0\x02\0\0\0| p/Microsoft Terminal Services/ o/Windows/ cpe:/o:microsoft:windows/a`)
	n.AddMatch("TCP_redis-server", `redis m|^.*redis_version:([.\d]+)\n|s p/Redis key-value store/ v/$1/ cpe:/a:redislabs:redis:$1/`)
	n.AddMatch("TCP_redis-server", `redis m|^-NOAUTH Authentication required.|s p/Redis key-value store/`)
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
