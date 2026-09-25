package judge

import "github.com/chainreactors/fingers/judge/internal/evidence"

// Layers are the roles a fingerprint plays in the software stack behind one
// response, as written to Framework.Judge.Layer. A page normally carries
// several fingerprints at different layers (CDN + web server + framework +
// application + libraries); each candidate is judged independently.
const (
	LayerCDN         = "cdn_or_waf"
	LayerServer      = "web_server"
	LayerRuntime     = "language_runtime"
	LayerFramework   = "web_framework"
	LayerApplication = "application"
	LayerFrontend    = "frontend_library"
	LayerDevice      = "os_or_device"
	LayerNotPresent  = "not_present"
)

// layerCriteria is the Choice criteria for classifying one candidate's layer.
var layerCriteria = map[string]string{
	LayerCDN:         "A CDN, reverse proxy cloud or web application firewall in front of the site",
	LayerServer:      "The HTTP server or proxy software, such as nginx, Apache httpd, IIS, Tomcat",
	LayerRuntime:     "A programming language or runtime, such as PHP, Java, ASP.NET, Node.js",
	LayerFramework:   "A backend web framework, such as Spring, Django, Laravel, ThinkPHP",
	LayerApplication: "The application whose interface this is: CMS, OA, admin console, SaaS app, forum, monitoring tool, search engine, or packaged static/browser-side tools; a documentation subject is not the application serving the docs",
	LayerFrontend:    "A browser-side library, UI kit, analytics or tag script, such as jQuery, Bootstrap, Google Analytics",
	LayerDevice:      "An operating system or the firmware of a hardware device such as a router, camera, NAS or firewall",
	LayerNotPresent:  "Not part of the software serving this response: only mentioned in text, or absent",
}

// NormalizeName folds the spellings different engines use for one product
// ("Apache-Tomcat", "apache tomcat", "Apache HTTP Server", "apache") into one
// key. It never merges names whose remaining letters differ.
func NormalizeName(name string) string { return evidence.NormalizeName(name) }
