// Package jev is the judgement layer on top of the rule engines, backed by
// TypeSafe's Jev (System One) model. It is not an engine: rules and code
// recall candidates, Jev only verifies and chooses (false positives, stack
// layer, primary application, page kind, generic page, version), and code
// makes the final call. Each capability is a Task; the tasks of a round share
// one request, so a page costs at most two.
//
// API reference: https://docs.typesafe.ai/api.md
package jev

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync/atomic"
	"time"
)

const (
	DefaultEndpoint = "https://api.typesafe.ai/v1/systemone"
	// Pin a versioned model: thresholds tuned against one version do not carry over.
	DefaultModel = "jev-1.13.0"
	EnvAPIKey    = "TYPESAFE_API_KEY"
)

// Question is one of noul / choice / score.
type Question struct {
	Type         string      `json:"type"`
	Instructions interface{} `json:"instructions"`
	Criteria     interface{} `json:"criteria,omitempty"`
}

func Noul(instructions interface{}) Question {
	return Question{Type: "noul", Instructions: instructions}
}

// Choice criteria maps option -> description (nil for none). Max 255 options.
func Choice(instructions interface{}, criteria map[string]interface{}) Question {
	return Question{Type: "choice", Instructions: instructions, Criteria: criteria}
}

// Score criteria is an ordered list of 2..10 level descriptions.
func Score(instructions interface{}, levels []string) Question {
	return Question{Type: "score", Instructions: instructions, Criteria: levels}
}

type request struct {
	State     interface{}         `json:"state"`
	Model     string              `json:"model"`
	Questions map[string]Question `json:"questions"`
}

type Answer struct {
	Type          string             `json:"type"`
	Noul          float64            `json:"noul,omitempty"`
	Choice        string             `json:"choice,omitempty"`
	Score         float64            `json:"score,omitempty"`
	Probabilities map[string]float64 `json:"probabilities,omitempty"`
	Confidence    float64            `json:"confidence,omitempty"`
}

type Usage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

type Response struct {
	Model   string            `json:"model"`
	Answers map[string]Answer `json:"answers"`
	Usage   Usage             `json:"usage"`
	Latency time.Duration     `json:"-"`
	Cached  bool              `json:"-"`
}

type Client struct {
	Endpoint   string
	Model      string
	APIKey     string
	HTTP       *http.Client
	MaxRetries int
	Cache      Cache // nil disables caching

	// Totals since creation, for cost monitoring; read with atomic.LoadInt64.
	Requests, CacheHits, InputTokens int64
}

// NewClient reads the API key from TYPESAFE_API_KEY when apiKey is empty.
func NewClient(apiKey string) (*Client, error) {
	if apiKey == "" {
		apiKey = os.Getenv(EnvAPIKey)
	}
	if apiKey == "" {
		return nil, fmt.Errorf("%s is not set", EnvAPIKey)
	}
	return &Client{
		Endpoint:   DefaultEndpoint,
		Model:      DefaultModel,
		APIKey:     apiKey,
		HTTP:       &http.Client{Timeout: 30 * time.Second},
		MaxRetries: 3,
	}, nil
}

type APIError struct {
	Status int
	Body   string
}

func (e *APIError) Error() string { return fmt.Sprintf("typesafe: http %d: %s", e.Status, e.Body) }

// Ask evaluates every question against one state in a single request.
// 429 / 529 are retried with exponential backoff. Most callers use Round,
// which also lets the cache match similar pages.
func (c *Client) Ask(ctx context.Context, state interface{}, questions map[string]Question) (*Response, error) {
	return c.ask(ctx, state, questions, nil, 0)
}

// ask caches under the hash of exact (the parts that must match exactly) and
// the page signature sig. With exact nil the whole request must match.
func (c *Client) ask(ctx context.Context, state interface{}, questions map[string]Question, exact []byte, sig uint64) (*Response, error) {
	// encoding/json sorts map keys, so equal requests marshal to equal bytes.
	body, err := json.Marshal(request{State: state, Model: c.Model, Questions: questions})
	if err != nil {
		return nil, err
	}
	if exact == nil {
		exact = body
	} else {
		exact = append([]byte(c.Model+"\x00"), exact...)
	}
	sum := sha256.Sum256(exact)
	key := hex.EncodeToString(sum[:])
	if c.Cache != nil {
		if raw, ok := c.Cache.Get(key, sig); ok {
			var out Response
			if json.Unmarshal(raw, &out) == nil {
				atomic.AddInt64(&c.CacheHits, 1)
				out.Cached = true
				return &out, nil
			}
		}
	}
	backoff := time.Second
	for attempt := 0; ; attempt++ {
		resp, raw, err := c.do(ctx, body)
		if err == nil {
			atomic.AddInt64(&c.Requests, 1)
			atomic.AddInt64(&c.InputTokens, int64(resp.Usage.InputTokens))
			if c.Cache != nil {
				c.Cache.Put(key, sig, raw)
			}
			return resp, nil
		}
		apiErr, ok := err.(*APIError)
		if !ok || (apiErr.Status != 429 && apiErr.Status != 529) || attempt >= c.MaxRetries {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(backoff):
		}
		backoff *= 2
	}
}

func (c *Client) do(ctx context.Context, body []byte) (*Response, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Content-Type", "application/json")

	start := time.Now()
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, nil, &APIError{Status: resp.StatusCode, Body: string(raw)}
	}
	var out Response
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, nil, fmt.Errorf("typesafe: decode response: %w", err)
	}
	out.Latency = time.Since(start)
	return &out, raw, nil
}
