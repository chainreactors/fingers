// Package jev is the TypeSafe Jev (System One) provider for package judge.
// It translates judge questions to Jev's wire format (binary -> noul) and
// sends them; everything else lives in judge.
//
// API reference: https://docs.typesafe.ai/api.md
package jev

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"github.com/chainreactors/fingers/judge"
)

const (
	DefaultEndpoint = "https://api.typesafe.ai/v1/systemone"
	// Pin a versioned model: the calibration below was measured on this one.
	DefaultModel = "jev-1.13.0"
	EnvAPIKey    = "TYPESAFE_API_KEY"
)

// Provider sends judge questions to Jev.
type Provider struct {
	Endpoint   string
	Model      string
	APIKey     string
	HTTP       *http.Client
	MaxRetries int // on 429 / 529, with exponential backoff

	// InputTokens sent so far; read with atomic.LoadInt64.
	InputTokens int64
}

// New reads the API key from TYPESAFE_API_KEY when apiKey is empty.
func New(apiKey string) (*Provider, error) {
	if apiKey == "" {
		apiKey = os.Getenv(EnvAPIKey)
	}
	if apiKey == "" {
		return nil, fmt.Errorf("%s is not set", EnvAPIKey)
	}
	return &Provider{
		Endpoint:   DefaultEndpoint,
		Model:      DefaultModel,
		APIKey:     apiKey,
		HTTP:       &http.Client{Timeout: 30 * time.Second},
		MaxRetries: 3,
	}, nil
}

// NewJudge is judge.New(New(apiKey)).
func NewJudge(apiKey string) (*judge.Judge, error) {
	p, err := New(apiKey)
	if err != nil {
		return nil, err
	}
	return judge.New(p), nil
}

func (p *Provider) ID() string { return "jev/" + p.Model }

// Calibration: on jev-1.13.0, a Noul of 0.5 separated real from false hits
// on labelled pages, and 42 of 46 versions picked at >= 0.9 were right.
func (p *Provider) Calibration() (float64, float64) { return 0.5, 0.9 }

type question struct {
	Type         string      `json:"type"`
	Instructions string      `json:"instructions"`
	Criteria     interface{} `json:"criteria,omitempty"`
}

type request struct {
	State     interface{}         `json:"state"`
	Model     string              `json:"model"`
	Questions map[string]question `json:"questions"`
}

type answer struct {
	Type          string             `json:"type"`
	Noul          float64            `json:"noul,omitempty"`
	Choice        string             `json:"choice,omitempty"`
	Score         float64            `json:"score,omitempty"`
	Probabilities map[string]float64 `json:"probabilities,omitempty"`
	Confidence    float64            `json:"confidence,omitempty"`
}

type response struct {
	Model   string            `json:"model"`
	Answers map[string]answer `json:"answers"`
	Usage   struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
}

func toJev(q judge.Question) question {
	out := question{Instructions: q.Instructions}
	switch q.Type {
	case judge.TypeBinary:
		out.Type = "noul"
		if len(q.Options) > 0 {
			out.Criteria = q.Options
		}
	case judge.TypeChoice:
		out.Type = "choice"
		opts := make(map[string]interface{}, len(q.Options))
		for k, v := range q.Options {
			if v == "" {
				opts[k] = nil // Jev's "no description"
			} else {
				opts[k] = v
			}
		}
		out.Criteria = opts
	case judge.TypeScore:
		out.Type = "score"
		out.Criteria = q.Levels
	}
	return out
}

type APIError struct {
	Status int
	Body   string
}

func (e *APIError) Error() string { return fmt.Sprintf("typesafe: http %d: %s", e.Status, e.Body) }

func (p *Provider) Judge(ctx context.Context, state interface{}, questions map[string]judge.Question) (map[string]judge.Answer, error) {
	req := request{State: state, Model: p.Model, Questions: make(map[string]question, len(questions))}
	for k, q := range questions {
		req.Questions[k] = toJev(q)
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	backoff := time.Second
	for attempt := 0; ; attempt++ {
		resp, err := p.do(ctx, body)
		if err == nil {
			atomic.AddInt64(&p.InputTokens, int64(resp.Usage.InputTokens))
			out := make(map[string]judge.Answer, len(resp.Answers))
			for k, a := range resp.Answers {
				out[k] = judge.Answer{Yes: a.Noul, Choice: a.Choice, Score: a.Score, Probabilities: a.Probabilities, Confidence: a.Confidence}
			}
			return out, nil
		}
		apiErr, ok := err.(*APIError)
		if !ok || (apiErr.Status != 429 && apiErr.Status != 529) || attempt >= p.MaxRetries {
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

func (p *Provider) do(ctx context.Context, body []byte) (*response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.Endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+p.APIKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &APIError{Status: resp.StatusCode, Body: string(raw)}
	}
	var out response
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("typesafe: decode response: %w", err)
	}
	return &out, nil
}
