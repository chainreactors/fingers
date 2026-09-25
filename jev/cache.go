package jev

import (
	"container/list"
	"math/bits"
	"sync"
)

// SimilarDistance is how many of the 64 signature bits two pages may differ
// in to share cached answers; 0 shares answers only between identical pages.
var SimilarDistance = 3

// Cache stores successful responses. key covers everything that must match
// exactly: model, questions and named evidence such as version strings. sig
// is the page's Signature: a cache may return the answers of a page whose
// signature is within SimilarDistance bits, so near-identical pages (the
// same product's login page on many hosts) cost one request. Jev answers an
// identical request identically, so an exact hit is always valid.
// Implementations must be safe for concurrent use.
type Cache interface {
	Get(key string, sig uint64) ([]byte, bool)
	Put(key string, sig uint64, value []byte)
}

// Similar reports whether two signatures are within SimilarDistance.
func Similar(a, b uint64) bool { return bits.OnesCount64(a^b) <= SimilarDistance }

// NewMemoryCache is an LRU cache holding up to size responses.
func NewMemoryCache(size int) Cache {
	return &memoryCache{size: size, order: list.New(), buckets: map[string][]*list.Element{}}
}

type memoryCache struct {
	mu      sync.Mutex
	size    int
	order   *list.List // front = most recent; values are *memoryEntry
	buckets map[string][]*list.Element
}

type memoryEntry struct {
	key   string
	sig   uint64
	value []byte
}

func (c *memoryCache) Get(key string, sig uint64) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var best *list.Element
	bestDist := 65
	for _, e := range c.buckets[key] {
		if d := bits.OnesCount64(e.Value.(*memoryEntry).sig ^ sig); d < bestDist {
			best, bestDist = e, d
		}
	}
	if best == nil || bestDist > SimilarDistance {
		return nil, false
	}
	c.order.MoveToFront(best)
	return best.Value.(*memoryEntry).value, true
}

func (c *memoryCache) Put(key string, sig uint64, value []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, e := range c.buckets[key] {
		if me := e.Value.(*memoryEntry); me.sig == sig {
			me.value = value
			c.order.MoveToFront(e)
			return
		}
	}
	c.buckets[key] = append(c.buckets[key], c.order.PushFront(&memoryEntry{key, sig, value}))
	for c.order.Len() > c.size {
		last := c.order.Back()
		c.order.Remove(last)
		me := last.Value.(*memoryEntry)
		bucket := c.buckets[me.key]
		for i, e := range bucket {
			if e == last {
				bucket = append(bucket[:i], bucket[i+1:]...)
				break
			}
		}
		if len(bucket) == 0 {
			delete(c.buckets, me.key)
		} else {
			c.buckets[me.key] = bucket
		}
	}
}
