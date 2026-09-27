package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/chainreactors/utils/jev"
)

// recordingProvider is the shared disk replay and accounting boundary.
// Schema 3 stores provider-neutral Claim/Ruling JSON. Provider.ID includes endpoint/model.
type recordingProvider struct {
	jev.Provider
	dir                 string
	offline             bool
	mu                  sync.Mutex
	calls, hits, claims int
}

func (p *recordingProvider) stats() (calls, hits, claims int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls, p.hits, p.claims
}

func (p *recordingProvider) Judge(ctx context.Context, state interface{}, claims map[string]jev.Claim) (map[string]jev.Ruling, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := jev.ValidateClaims(claims); err != nil {
		return nil, err
	}
	data, err := json.Marshal([]interface{}{"claim-report-v3", p.ID(), state, claims})
	if err != nil {
		return nil, err
	}
	path := filepath.Join(p.dir, digest(data)+".json")
	p.mu.Lock()
	p.claims += len(claims)
	p.mu.Unlock()
	var rulings map[string]jev.Ruling
	if cached, err := os.ReadFile(path); err == nil && json.Unmarshal(cached, &rulings) == nil && jev.ValidateRulings(claims, rulings) == nil {
		p.mu.Lock()
		p.hits++
		p.mu.Unlock()
		return rulings, nil
	}
	if p.offline {
		return nil, fmt.Errorf("offline cache miss: %s", filepath.Base(path))
	}
	p.mu.Lock()
	p.calls++
	p.mu.Unlock()
	rulings, err = p.Provider.Judge(ctx, state, claims)
	if err == nil {
		err = jev.ValidateRulings(claims, rulings)
	}
	if err != nil {
		return nil, err
	}
	if err := writeCache(path, rulings); err != nil {
		return nil, err
	}
	return rulings, nil
}

func writeCache(path string, value interface{}) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".claim-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
