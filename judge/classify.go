package judge

// Kind is what a page is, set by Classify.
type Kind string

const (
	KindLogin      Kind = "login"
	KindDefault    Kind = "default_install"
	KindError      Kind = "error_page"
	KindDirListing Kind = "directory_listing"
	KindConsole    Kind = "app_console"
	KindContent    Kind = "normal_content"
	KindAPI        Kind = "api_response"
)

var pageKinds = map[string]string{
	string(KindLogin):      "A sign-in form or authentication page",
	string(KindDefault):    "The stock page a web server or product shows right after installation",
	string(KindError):      "A framework or server error page such as 404 or 500",
	string(KindDirListing): "An auto-generated file index of a directory",
	string(KindConsole):    "The main interface or loading screen of a web application or management console, including packaged static/browser-side tools and search applications",
	string(KindContent):    "An ordinary website page: article, company site, shop, forum, blog, status page",
	string(KindAPI):        "A machine-readable API response rather than a web page",
}

// classifyRound asks what the page is and whether it is the stock page of a
// packaged product, writing the answers to kind and generic. It needs no
// fingerprints: spray can use it alone for 404 detection and
// prioritisation. A generic page without an accepted application is a
// candidate for a new fingerprint.
func classifyRound(r *round, kind *Kind, generic *bool) {
	r.add("page_kind", Choice("What kind of page is this HTTP response?", pageKinds), func(a Answer) { *kind = Kind(a.Choice) })
	r.add("generic", BinaryWith("Is this page the stock interface of a packaged software product, framework or device, "+
		"so that the same page would appear on many unrelated deployments?",
		"Login, console, default or error page, packaged search application or static/browser-side tools shipped by a product; no login or backend is required; only branding, host names or data differ between installs",
		"Content written by one organization for its own purpose: articles, company pages, shops, forums, custom-built portals"),
		func(a Answer) { *generic = a.Yes >= r.judge.Threshold })
}
