package judge

import (
	"container/list"
	"math/bits"
	"sync"
)

// Cache stores answers, one per question. key covers everything that must
// match exactly: model, question and named evidence such as version strings.
// sig is the page's signature: Get may return the answer stored for a page
// whose signature is within distance bits (Judge.SimilarDistance), so
// near-identical pages (one product's login page on many hosts, one site's
// 404 page on every path) are asked once. Providers answer identical input
// identically, so an exact hit is always valid. Implementations must be safe for concurrent use; the
// in-memory NewMemoryCache is the default, a shared one (redis, disk) lets
// several scanners share answers.
type Cache interface {
	Get(key string, sig uint64, distance int) ([]byte, bool)
	Put(key string, sig uint64, value []byte)
}

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

func (c *memoryCache) Get(key string, sig uint64, distance int) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var best *list.Element
	bestDist := 65
	for _, e := range c.buckets[key] {
		if d := bits.OnesCount64(e.Value.(*memoryEntry).sig ^ sig); d < bestDist {
			best, bestDist = e, d
		}
	}
	if best == nil || bestDist > distance {
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
