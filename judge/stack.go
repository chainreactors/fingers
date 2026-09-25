package judge

import (
	"strings"
	"unicode"
)

// Layer is the role a fingerprint plays in the software stack behind one
// response. A page normally carries several fingerprints at different layers
// (CDN + web server + framework + application + libraries); each candidate is
// judged independently, and the layer decides how results combine.
type Layer string

const (
	LayerCDN         Layer = "cdn_or_waf"
	LayerServer      Layer = "web_server"
	LayerRuntime     Layer = "language_runtime"
	LayerFramework   Layer = "web_framework"
	LayerApplication Layer = "application"
	LayerFrontend    Layer = "frontend_library"
	LayerDevice      Layer = "os_or_device"
	LayerNotPresent  Layer = "not_present"
)

// layerCriteria is the Choice criteria for classifying one candidate's layer.
var layerCriteria = map[string]string{
	string(LayerCDN):         "A CDN, reverse proxy cloud or web application firewall in front of the site",
	string(LayerServer):      "The HTTP server or proxy software, such as nginx, Apache httpd, IIS, Tomcat",
	string(LayerRuntime):     "A programming language or runtime, such as PHP, Java, ASP.NET, Node.js",
	string(LayerFramework):   "A backend web framework, such as Spring, Django, Laravel, ThinkPHP",
	string(LayerApplication): "The application or product the page belongs to: CMS, OA, admin console, SaaS app, forum, monitoring tool",
	string(LayerFrontend):    "A browser-side library, UI kit, analytics or tag script, such as jQuery, Bootstrap, Google Analytics",
	string(LayerDevice):      "An operating system or the firmware of a hardware device such as a router, camera, NAS or firewall",
	string(LayerNotPresent):  "Not part of the software serving this response: only mentioned in text, or absent",
}

var genericSuffixes = []string{"companyproducts", "公司产品", "product", "products", "产品", "operatingsystem", "操作系统", "system"}

// genericWords are trailing words engines add to a product name ("Apache
// HTTP Server", "apache-web-server", "Discuz! X"). They are dropped only as
// whole words, so "lighttpd" keeps its "httpd".
var genericWords = map[string]bool{"http": true, "httpd": true, "server": true, "web": true, "webserver": true, "x": true, "cms": true, "oa": true}

// NormalizeName folds the spellings different engines use for one product
// ("Apache-Tomcat", "apache tomcat", "Apache HTTP Server", "apache") into one
// key. It never merges names whose remaining letters differ.
func NormalizeName(name string) string {
	words := strings.FieldsFunc(strings.ToLower(name), func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) })
	for len(words) > 1 && genericWords[words[len(words)-1]] {
		words = words[:len(words)-1]
	}
	key := strings.Join(words, "")
	for _, s := range genericSuffixes {
		if len(key) > len(s)+2 && strings.HasSuffix(key, s) {
			key = strings.TrimSuffix(key, s)
		}
	}
	return key
}
