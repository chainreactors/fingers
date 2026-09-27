package judge

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/chainreactors/fingers/common"
	"github.com/chainreactors/utils/jev"
)

const jenkinsRaw = "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nX-Jenkins: 2.401.3\r\nSet-Cookie: JSESSIONID.1=x; Path=/\r\nContent-Type: text/html\r\n\r\n" +
	`<html><head><title>Sign in [Jenkins]</title><script src="/static/prototype.js"></script></head>` +
	`<body><script>var x=1;</script><p>We moved here from WordPress.</p>` +
	`<input name="j_username" type="text"><input name="j_password" type="password"></body></html>`

// mock is a Provider ruling from a table keyed by claim kind and the
// product named in backticks; it records the claim keys of each call.
type mock struct {
	mu         sync.Mutex
	delay      time.Duration
	calls      int64
	requests   [][]string
	fail       bool
	confidence float64
	presence   map[string]string // product -> presence option
	versions   map[string]string // product -> version picked, if among the options
	coverage   string
	lastState  map[string]interface{}
}

func newMock() *mock {
	return &mock{
		confidence: 0.95,
		presence:   map[string]string{"wordpress": OptionMentioned, "apache tomcat": OptionRunning, "prototype": OptionRunning},
		versions:   map[string]string{"jenkins": "2.401.3", "nginx": "1.24.0"},
	}
}

// named is the first product named in backticks, skipping state field names.
func named(q jev.Claim) string {
	parts := strings.Split(q.Statement, "`")
	for i := 1; i < len(parts); i += 2 {
		if parts[i] != "version_strings" && !strings.HasPrefix(parts[i], "matches.") {
			return parts[i]
		}
	}
	return ""
}

func (m *mock) ID() string { return "mock" }

func (m *mock) Judge(ctx context.Context, state interface{}, claims map[string]jev.Claim) (map[string]jev.Ruling, error) {
	atomic.AddInt64(&m.calls, 1)
	time.Sleep(m.delay)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return nil, errors.New("provider down")
	}
	data, _ := json.Marshal(state)
	_ = json.Unmarshal(data, &m.lastState)
	rulings := map[string]jev.Ruling{}
	var keys []string
	for k, q := range claims {
		keys = append(keys, k)
		name := strings.ToLower(named(q))
		switch {
		case strings.HasPrefix(k, "presence_"):
			v := m.presence[name]
			if v == "" {
				v = jev.OptionInsufficient
			}
			rulings[k] = jev.Ruling{Option: v, Confidence: m.confidence}
		case strings.HasPrefix(k, "version_"):
			option := notStated
			if v, ok := m.versions[name]; ok {
				if _, offered := q.Options[v]; offered {
					option = v
				}
			}
			rulings[k] = jev.Ruling{Option: option, Confidence: m.confidence}
		case k == "coverage":
			rulings[k] = jev.Ruling{Option: m.coverage, Confidence: m.confidence}
		default:
			rulings[k] = jev.Ruling{Option: jev.OptionInsufficient, Confidence: m.confidence}
		}
	}
	sort.Strings(keys)
	m.requests = append(m.requests, keys)
	return rulings, nil
}

func testFrames() common.Frameworks {
	fs := common.Frameworks{}
	fs.Add(common.NewFramework("nginx", common.FrameFromFingers))
	fs.Add(common.NewFramework("wordpress", common.FrameFromGoby))
	fs.Add(common.NewFramework("jenkins", common.FrameFromFingerprintHub))
	fs.Add(common.NewFramework("apache-tomcat", common.FrameFromFingers))
	fs.Add(common.NewFramework("apache tomcat", common.FrameFromWappalyzer))
	fs.Add(common.NewFramework("hsts", common.FrameFromWappalyzer))
	return fs
}

// bodyRaw states versions only in the body, so the provider has to pick them.
const bodyRaw = "HTTP/1.1 200 OK\r\nServer: nginx\r\nSet-Cookie: JSESSIONID.1=x; Path=/\r\n\r\n" +
	`<html><head><title>Sign in [Jenkins]</title><script src="/static/prototype.js"></script></head>` +
	`<body><p>We moved here from WordPress.</p><footer>Jenkins 2.401.3, nginx 1.24.0</footer></body></html>`

type rulingProvider func(map[string]jev.Claim) map[string]jev.Ruling

func (rulingProvider) ID() string { return "ruling-provider" }

func (p rulingProvider) Judge(_ context.Context, _ interface{}, claims map[string]jev.Claim) (map[string]jev.Ruling, error) {
	return p(claims), nil
}

type failVersionProvider struct{ *mock }

func (p failVersionProvider) Judge(ctx context.Context, state interface{}, claims map[string]jev.Claim) (map[string]jev.Ruling, error) {
	if _, ok := claims["version_jenkins"]; ok {
		return nil, errors.New("version unavailable")
	}
	return p.mock.Judge(ctx, state, claims)
}
