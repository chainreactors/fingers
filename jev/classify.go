package jev

// PageKinds is the Choice criteria for Page.Kind.
var PageKinds = map[string]interface{}{
	"login":             "A sign-in form or authentication page",
	"default_install":   "The stock page a web server or product shows right after installation",
	"error_page":        "A framework or server error page such as 404 or 500",
	"directory_listing": "An auto-generated file index of a directory",
	"app_console":       "The main interface or loading screen of a web application or management console",
	"normal_content":    "An ordinary website page: article, company site, shop, forum, blog, status page",
	"api_response":      "A machine-readable API response rather than a web page",
}

// Classify judges the page itself and writes Page.Kind and Page.Generic. It
// needs no fingerprints: spray can use it alone for 404 detection and
// prioritisation. A generic page without an accepted application is a
// candidate for a new fingerprint.
func Classify(r *Round) {
	p := r.page
	r.Add("page_kind", Choice("What kind of page is this HTTP response?", PageKinds), func(a Answer) { p.Kind = a.Choice })
	r.Add("generic", Question{
		Type: "noul",
		Instructions: "Is this page the stock interface of a packaged software product, framework or device, " +
			"so that the same page would appear on many unrelated deployments?",
		Criteria: map[string]string{
			"true":  "Login, console, default or error page shipped by a product; only branding, host names or data differ between installs",
			"false": "Content written by one organization for its own purpose: articles, company pages, shops, forums, custom-built portals",
		},
	}, func(a Answer) { p.Generic = a.Noul >= Threshold })
}
