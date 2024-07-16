package wappalyzer

import (
	"bytes"
	"encoding/json"
	"github.com/chainreactors/fingers/common"
	"github.com/chainreactors/fingers/resources"
	"strings"
)

// Wappalyze is a client for working with tech detection
type Wappalyze struct {
	fingerprints *CompiledFingerprints
}

// New creates a new tech detection instance
func NewWappalyzeEngine() (*Wappalyze, error) {
	wappalyze := &Wappalyze{
		fingerprints: &CompiledFingerprints{
			Apps: make(map[string]*CompiledFingerprint),
		},
	}
	err := wappalyze.Compile()
	if err != nil {
		return nil, err
	}
	return wappalyze, nil
}

func (s *Wappalyze) Compile() error {
	err := s.loadFingerprints()
	if err != nil {
		return err
	}
	return nil
}

// loadFingerprints loads the fingerprints and compiles them
func (s *Wappalyze) loadFingerprints() error {
	var fingerprintsStruct Fingerprints
	err := json.Unmarshal(resources.WappalyzerData, &fingerprintsStruct)
	if err != nil {
		return err
	}

	for i, fingerprint := range fingerprintsStruct.Apps {
		s.fingerprints.Apps[i] = compileFingerprint(fingerprint)
	}
	return nil
}

// Fingerprint identifies technologies on a target,
// based on the received response headers and body.
//
// Body should not be mutated while this function is being called, or it may
// lead to unexpected things.
func (s *Wappalyze) Fingerprint(headers map[string][]string, body []byte) common.Frameworks {
	uniqueFingerprints := make(common.Frameworks)

	// Lowercase everything that we have received to check
	normalizedBody := bytes.ToLower(body)
	normalizedHeaders := s.normalizeHeaders(headers)

	// Run header based fingerprinting if the number
	// of header checks if more than 0.
	uniqueFingerprints.Merge(s.checkHeaders(normalizedHeaders))

	cookies := s.findSetCookie(normalizedHeaders)
	// Run cookie based fingerprinting if we have a set-cookie header
	if len(cookies) > 0 {
		uniqueFingerprints.Merge(s.checkCookies(cookies))
	}

	// Check for stuff in the body finally
	uniqueFingerprints.Merge(s.checkBody(normalizedBody))
	return uniqueFingerprints
}

// FingerprintWithTitle identifies technologies on a target,
// based on the received response headers and body.
// It also returns the title of the page.
//
// Body should not be mutated while this function is being called, or it may
// lead to unexpected things.
func (s *Wappalyze) FingerprintWithTitle(headers map[string][]string, body []byte) (common.Frameworks, string) {
	uniqueFingerprints := make(common.Frameworks)

	// Lowercase everything that we have received to check
	normalizedBody := bytes.ToLower(body)
	normalizedHeaders := s.normalizeHeaders(headers)

	// Run header based fingerprinting if the number
	// of header checks if more than 0.

	uniqueFingerprints.Merge(s.checkHeaders(normalizedHeaders))

	cookies := s.findSetCookie(normalizedHeaders)
	// Run cookie based fingerprinting if we have a set-cookie header
	if len(cookies) > 0 {
		uniqueFingerprints.Merge(s.checkCookies(cookies))
	}

	// Check for stuff in the body finally
	if strings.Contains(normalizedHeaders["content-type"], "text/html") {
		bodyTech := s.checkBody(normalizedBody)
		uniqueFingerprints.Merge(bodyTech)
		title := s.getTitle(body)
		return uniqueFingerprints, title
	}
	return uniqueFingerprints, ""
}

// FingerprintWithInfo identifies technologies on a target,
// based on the received response headers and body.
// It also returns basic information about the technology, such as description
// and website URL.
//
// Body should not be mutated while this function is being called, or it may
// lead to unexpected things.
func (s *Wappalyze) FingerprintWithInfo(headers map[string][]string, body []byte) map[string]AppInfo {
	apps := s.Fingerprint(headers, body)
	result := make(map[string]AppInfo, len(apps))

	for app := range apps {
		if fingerprint, ok := s.fingerprints.Apps[app]; ok {
			result[app] = AppInfo{
				Description: fingerprint.description,
				Website:     fingerprint.website,
				CPE:         fingerprint.cpe,
			}
		}
	}

	return result
}

// FingerprintWithCats identifies technologies on a target,
// based on the received response headers and body.
// It also returns categories information about the technology, is there's any
// Body should not be mutated while this function is being called, or it may
// lead to unexpected things.
func (s *Wappalyze) FingerprintWithCats(headers map[string][]string, body []byte) map[string]CatsInfo {
	apps := s.Fingerprint(headers, body)
	result := make(map[string]CatsInfo, len(apps))

	for app := range apps {
		if fingerprint, ok := s.fingerprints.Apps[app]; ok {
			result[app] = CatsInfo{
				Cats: fingerprint.cats,
			}
		}
	}

	return result
}
