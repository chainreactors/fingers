package judge

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// Judge puts a Provider to work: it answers questions from the cache where
// it can, merges concurrent rounds asking the same questions about similar
// pages, and holds the thresholds the capabilities decide with. One Judge is
// meant to be shared by every page of a scan.
type Judge struct {
	Provider Provider
	// Cache keeps answers per question, so a question asked again about the
	// same or a similar page (see SimilarDistance) is not sent again, however
	// questions are grouped into rounds. New sets an in-memory cache; nil
	// disables it. Concurrent rounds are merged either way.
	Cache Cache
	// Threshold is the Yes probability that counts as "yes"; VersionConfidence
	// the confidence at which a picked version is adopted.
	Threshold, VersionConfidence float64

	// Totals, for cost monitoring; read with atomic.LoadInt64. Requests went
	// to the provider; CacheHits are rounds answered without one.
	Requests, CacheHits int64

	mu      sync.Mutex
	flights map[string][]*flight
}

// DefaultCacheSize is the number of answers the cache New creates holds.
const DefaultCacheSize = 1 << 16

// New returns a Judge with an in-memory cache and the provider's
// calibration, or 0.5 / 0.9 for providers that report none.
func New(p Provider) *Judge {
	j := &Judge{Provider: p, Cache: NewMemoryCache(DefaultCacheSize), Threshold: 0.5, VersionConfidence: 0.9}
	if c, ok := p.(Calibrated); ok {
		j.Threshold, j.VersionConfidence = c.Calibration()
	}
	return j
}

// Ask asks questions about state, which must match exactly for cached
// answers to apply. Most callers use Round, which also matches similar pages.
func (j *Judge) Ask(ctx context.Context, state interface{}, questions map[string]Question) (map[string]Answer, error) {
	scope, err := json.Marshal(state)
	if err != nil {
		return nil, err
	}
	return j.ask(ctx, state, questions, scope, 0)
}

// flight is a request in progress; rounds asking the same questions about a
// similar page wait for it instead of sending their own.
type flight struct {
	sig     uint64
	done    chan struct{}
	answers map[string]Answer // by cache key; nil if the request failed
}

// ask answers questions from the cache where it can and sends the rest in
// one request. A cached answer applies when the question, the scope (what
// must match exactly besides the question) and the model are equal and the
// page signature sig is similar.
func (j *Judge) ask(ctx context.Context, state interface{}, questions map[string]Question, scope []byte, sig uint64) (map[string]Answer, error) {
	answers := make(map[string]Answer, len(questions))
	keys := make(map[string]string, len(questions)) // question key -> cache key
	missing := map[string]Question{}
	var pending []string
	for k, q := range questions {
		qj, err := json.Marshal(q)
		if err != nil {
			return nil, err
		}
		h := sha256.New()
		for _, part := range [][]byte{[]byte(j.Provider.ID()), scope, qj} {
			h.Write(part)
			h.Write([]byte{0})
		}
		ck := hex.EncodeToString(h.Sum(nil))
		keys[k] = ck
		if a, ok := j.cached(ck, sig); ok {
			answers[k] = a
			continue
		}
		missing[k] = q
		pending = append(pending, ck)
	}
	if len(missing) == 0 {
		atomic.AddInt64(&j.CacheHits, 1)
		return answers, nil
	}
	sort.Strings(pending)
	fk := strings.Join(pending, ",")
	for {
		f, leader := j.join(fk, sig)
		if !leader {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-f.done:
			}
			if f.answers == nil {
				continue // the request we waited on failed: try again, possibly as the leader
			}
			for k := range missing {
				answers[k] = f.answers[keys[k]]
			}
			atomic.AddInt64(&j.CacheHits, 1)
			return answers, nil
		}
		got, err := j.Provider.Judge(ctx, state, missing)
		var byKey map[string]Answer
		if err == nil {
			atomic.AddInt64(&j.Requests, 1)
			byKey = make(map[string]Answer, len(got))
			for k, a := range got {
				answers[k] = a
				if ck, ok := keys[k]; ok {
					byKey[ck] = a
					if j.Cache != nil {
						if v, err := json.Marshal(a); err == nil {
							j.Cache.Put(ck, sig, v)
						}
					}
				}
			}
		}
		j.land(fk, f, byKey)
		if err != nil {
			return nil, err
		}
		return answers, nil
	}
}

func (j *Judge) cached(key string, sig uint64) (Answer, bool) {
	var a Answer
	if j.Cache == nil {
		return a, false
	}
	v, ok := j.Cache.Get(key, sig)
	return a, ok && json.Unmarshal(v, &a) == nil
}

func (j *Judge) join(key string, sig uint64) (*flight, bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, f := range j.flights[key] {
		if Similar(f.sig, sig) {
			return f, false
		}
	}
	if j.flights == nil {
		j.flights = map[string][]*flight{}
	}
	f := &flight{sig: sig, done: make(chan struct{})}
	j.flights[key] = append(j.flights[key], f)
	return f, true
}

func (j *Judge) land(key string, f *flight, answers map[string]Answer) {
	j.mu.Lock()
	fs := j.flights[key]
	for i, x := range fs {
		if x == f {
			fs = append(fs[:i], fs[i+1:]...)
			break
		}
	}
	if len(fs) == 0 {
		delete(j.flights, key)
	} else {
		j.flights[key] = fs
	}
	j.mu.Unlock()
	f.answers = answers
	close(f.done)
}
