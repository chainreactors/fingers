package fingers

import "testing"

// A version written on one page's frameworks must not reach the next page:
// alias attributes are shared by every page.
func TestMergeFrameworksCopiesAliasAttributes(t *testing.T) {
	e, err := NewEngine(FingersEngine, WappalyzerEngine, GobyEngine, EHoleEngine, FingerPrintEngine)
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte("HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n<meta name=\"generator\" content=\"WordPress\">" +
		"<link href='/wp-content/themes/x/style.css'><script src='/wp-includes/js/wp-emoji-release.min.js'></script>")
	for i := 0; i < 30; i++ { // which pointer survives depends on map order
		a, _ := e.DetectContent(raw)
		for _, f := range a {
			f.Attributes.Version = "9.9.9"
		}
		b, _ := e.DetectContent(raw)
		for _, f := range b {
			if f.Version == "9.9.9" {
				t.Fatalf("version leaked into the next page: %s", f.Name)
			}
		}
	}
}
