package fingers

import (
	"strings"
	"testing"
)

func rawHTTP(body string) []byte {
	return []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" + body)
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

// TestLevelSendDataRecognition verifies that:
// 1) level 0 performs no active probing,
// 2) level 1 uses finger-level send_data only,
// 3) level 2 additionally uses rule-level send_data.
func TestLevelSendDataRecognition(t *testing.T) {
	const (
		fingerPath = "/finger-level"
		rulePath   = "/rule-level"
	)

	finger := &Finger{
		Name:        "level-test",
		Protocol:    HTTPProtocol,
		DefaultPort: []string{"80"},
		SendDataStr: fingerPath,
		Rules: Rules{
			{
				Regexps: &Regexps{
					Body: []string{"finger-hit"},
				},
				Level: 1,
			},
			{
				Regexps: &Regexps{
					Body: []string{"rule-hit"},
				},
				SendDataStr: rulePath,
				Level:       2,
			},
		},
	}

	if err := finger.Compile(false); err != nil {
		t.Fatalf("failed to compile finger: %v", err)
	}

	responses := map[string][]byte{
		fingerPath: rawHTTP("<title>finger-hit</title>"),
		rulePath:   rawHTTP("<title>rule-hit</title>"),
	}

	makeSender := func(sent *[]string) Sender {
		return Sender(func(data []byte) ([]byte, bool) {
			path := string(data)
			*sent = append(*sent, path)
			resp, ok := responses[path]
			return resp, ok
		})
	}

	// level 0: passive only, should not send and should not match.
	{
		var sent []string
		frame, _, ok := finger.Match(NewContent(rawHTTP("no-hit"), "", true), 0, makeSender(&sent))
		if ok || frame != nil {
			t.Fatalf("level 0 should not match, got ok=%v frame=%v", ok, frame)
		}
		if len(sent) != 0 {
			t.Fatalf("level 0 should not send, sent=%v", sent)
		}
	}

	// level 1: should send finger-level only and match via finger-level response.
	{
		var sent []string
		frame, _, ok := finger.Match(NewContent(rawHTTP("no-hit"), "", true), 1, makeSender(&sent))
		if !ok || frame == nil {
			t.Fatalf("level 1 should match via finger send_data")
		}
		if !contains(sent, fingerPath) {
			t.Fatalf("level 1 should send finger path %q, sent=%v", fingerPath, sent)
		}
		if contains(sent, rulePath) {
			t.Fatalf("level 1 should not send rule path %q, sent=%v", rulePath, sent)
		}
	}

	// level 2: should send both finger-level and rule-level.
	{
		var sent []string
		frame, _, ok := finger.Match(NewContent(rawHTTP("no-hit"), "", true), 2, makeSender(&sent))
		if !ok || frame == nil {
			t.Fatalf("level 2 should match via active probing")
		}
		if !contains(sent, fingerPath) {
			t.Fatalf("level 2 should send finger path %q, sent=%v", fingerPath, sent)
		}
		if !contains(sent, rulePath) {
			t.Fatalf("level 2 should send rule path %q, sent=%v", rulePath, sent)
		}

		// Sanity-check that the level 2 run actually used active content.
		if frame.Version == "" && !strings.Contains(frame.Name, "level-test") {
			t.Fatalf("unexpected framework returned at level 2: %#v", frame)
		}
	}
}

func TestMatchDetail_Passive(t *testing.T) {
	finger := &Finger{
		Name:              "rule-tag-test",
		Protocol:          HTTPProtocol,
		EnableMatchDetail: true,
		Rules: Rules{
			{
				Regexps: &Regexps{
					Body: []string{"first-hit"},
				},
			},
			{
				Regexps: &Regexps{
					Body: []string{"second-hit"},
				},
			},
		},
	}

	if err := finger.Compile(false); err != nil {
		t.Fatalf("failed to compile finger: %v", err)
	}

	frame, _, ok := finger.Match(NewContent(rawHTTP("second-hit"), "", true), 0, nil)
	if !ok || frame == nil {
		t.Fatalf("expected passive match to succeed")
	}
	if frame.MatchDetail == nil {
		t.Fatalf("expected match detail to be populated")
	}
	if frame.MatchDetail.RuleIndex != 1 {
		t.Fatalf("expected rule index 1, got %d", frame.MatchDetail.RuleIndex)
	}
	if frame.MatchDetail.MatcherType != "body" {
		t.Fatalf("expected matcher type body, got %q", frame.MatchDetail.MatcherType)
	}
	if frame.MatchDetail.MatcherIndex != 0 {
		t.Fatalf("expected matcher index 0, got %d", frame.MatchDetail.MatcherIndex)
	}
	if frame.MatchDetail.SendData != "" {
		t.Fatalf("expected passive match detail send_data to be empty, got %q", frame.MatchDetail.SendData)
	}
}

func TestMatchDetail_ActiveSendData(t *testing.T) {
	const (
		fingerPath = "/finger-active"
		rulePath   = "/rule-active"
	)

	finger := &Finger{
		Name:              "active-detail-test",
		Protocol:          HTTPProtocol,
		EnableMatchDetail: true,
		SendDataStr:       fingerPath,
		Rules: Rules{
			{
				Regexps: &Regexps{
					Body: []string{"rule-hit"},
				},
				SendDataStr: rulePath,
				Level:       2,
			},
		},
	}

	if err := finger.Compile(false); err != nil {
		t.Fatalf("failed to compile finger: %v", err)
	}

	sender := Sender(func(data []byte) ([]byte, bool) {
		switch string(data) {
		case fingerPath:
			return rawHTTP("no-hit"), true
		case rulePath:
			return rawHTTP("rule-hit"), true
		default:
			return nil, false
		}
	})

	frame, _, ok := finger.ActiveMatch(2, sender)
	if !ok || frame == nil {
		t.Fatalf("expected active match to succeed")
	}
	if frame.MatchDetail == nil {
		t.Fatalf("expected match detail to be populated")
	}
	if frame.MatchDetail.SendData != rulePath {
		t.Fatalf("expected send_data %q, got %q", rulePath, frame.MatchDetail.SendData)
	}
}
