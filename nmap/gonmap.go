package gonmap

import (
	"regexp"
	"strings"
)

// r["PROBE"] 总探针数、r["MATCH"] 总指纹数 、r["USED_PROBE"] 已使用探针数、r["USED_MATCH"] 已使用指纹数
// 全局模式已移除，只支持实例模式，使用 NewWithData 创建实例

// NewWithData 使用指定的数据初始化 Nmap 实例
func NewWithData(probesData, servicesData []byte) *Nmap {
	//初始化NMAP探针库
	n := &Nmap{
		exclude:        emptyPortList,
		probeNameMap:   make(map[string]*Probe),
		rarityProbeMap: make(map[int][]*Probe),
		portProbeMap:   make(map[int]ProbeList),

		sslSecondProbeMap: []string{"TCP_TerminalServerCookie", "TCP_TerminalServer"},
		sslProbeMap:       []string{"TCP_TLSSessionReq", "TCP_SSLSessionReq", "TCP_SSLv23SessionReq"},
	}
	for i := 0; i <= 65535; i++ {
		n.portProbeMap[i] = []string{}
	}

	// 初始化ServicesData - 从bytes加载（已解压缩）
	n.loadServicesFromBytes(servicesData)

	// 从提供的数据加载探针数据（已解压缩）
	n.loadProbesFromBytes(probesData)

	//修复fallback
	n.fixFallback()

	// 自定义指纹 (使用实例方法)
	n.addCustomMatches()

	// 优化探针 (使用实例方法)
	n.optimizeProbes()

	return n
}

var regexpFirstNum = regexp.MustCompile(`^\d`)

func FixProtocol(oldProtocol string) string {
	//进行最后输出修饰
	if oldProtocol == "ssl/http" {
		return "https"
	}
	if oldProtocol == "http-proxy" {
		return "http"
	}
	if oldProtocol == "ms-wbt-server" {
		return "rdp"
	}
	if oldProtocol == "microsoft-ds" {
		return "smb"
	}
	if oldProtocol == "netbios-ssn" {
		return "netbios"
	}
	if oldProtocol == "oracle-tns" {
		return "oracle"
	}
	if oldProtocol == "msrpc" {
		return "rpc"
	}
	if oldProtocol == "ms-sql-s" {
		return "mssql"
	}
	if oldProtocol == "domain" {
		return "dns"
	}
	if oldProtocol == "svnserve" {
		return "svn"
	}
	if oldProtocol == "ibm-db2" {
		return "db2"
	}
	if oldProtocol == "socks-proxy" {
		return "socks5"
	}
	if len(oldProtocol) > 4 {
		if oldProtocol[:4] == "ssl/" {
			return oldProtocol[4:] + "-ssl"
		}
	}
	if regexpFirstNum.MatchString(oldProtocol) {
		oldProtocol = "S" + oldProtocol
	}
	oldProtocol = strings.ReplaceAll(oldProtocol, "_", "-")
	return oldProtocol
}
