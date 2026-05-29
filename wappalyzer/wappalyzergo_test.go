package wappalyzer

import (
	"testing"

	"github.com/chainreactors/fingers/resources"
	"github.com/stretchr/testify/require"
)

func TestCookiesDetect(t *testing.T) {
	wappalyzer, err := NewWappalyzeEngine(resources.WappalyzerData)
	require.Nil(t, err, "could not create wappalyzer")

	matches := wappalyzer.Fingerprint(map[string][]string{
		"Set-Cookie": {"_uetsid=ABCDEF"},
	}, []byte(""))

	require.Contains(t, matches, "microsoft advertising", "Could not get correct match")

	t.Run("position", func(t *testing.T) {
		wappalyzerClient, _ := NewWappalyzeEngine(resources.WappalyzerData)

		fingerprints := wappalyzerClient.Fingerprint(map[string][]string{
			"Set-Cookie": {"path=/; jsessionid=111; path=/, jsessionid=111;"},
		}, []byte(""))
		fingerprints1 := wappalyzerClient.Fingerprint(map[string][]string{
			"Set-Cookie": {"jsessionid=111; path=/, XSRF-TOKEN=; expires=test, path=/ laravel_session=eyJ*"},
		}, []byte(""))

		require.Contains(t, fingerprints, "java", "could not get correct fingerprints")
		require.Contains(t, fingerprints1, "java", "could not get correct fingerprints")
		require.Contains(t, fingerprints1, "laravel", "could not get correct fingerprints")
	})
}

func TestHeadersDetect(t *testing.T) {
	wappalyzer, err := NewWappalyzeEngine(resources.WappalyzerData)
	require.Nil(t, err, "could not create wappalyzer")

	matches := wappalyzer.Fingerprint(map[string][]string{
		"Server": {"now"},
	}, []byte(""))

	require.Contains(t, matches, "vercel", "Could not get correct match")
}

func TestBodyDetect(t *testing.T) {
	wappalyzer, err := NewWappalyzeEngine(resources.WappalyzerData)
	require.Nil(t, err, "could not create wappalyzer")

	t.Run("meta", func(t *testing.T) {
		matches := wappalyzer.Fingerprint(map[string][]string{}, []byte(`<html>
<head>
<meta name="generator" content="mura cms 1">
</head>
</html>`))
		require.Contains(t, matches, "mura cms", "Could not get correct match")
	})

	t.Run("html-implied", func(t *testing.T) {
		matches := wappalyzer.Fingerprint(map[string][]string{}, []byte(`<html data-ng-app="rbschangeapp">
<head>
</head>
<body>
</body>
</html>`))
		require.Contains(t, matches, "angularjs", "Could not get correct implied match")
		require.Contains(t, matches, "proximis unified commerce", "Could not get correct match")
	})
}
