package jev

import (
	"sort"
	"strings"
	"unicode/utf8"
)

// Retriever finds fingerprint names that literally occur in a page. Every
// candidate handed to Jev is therefore anchored to evidence found by code,
// so Jev only ranks and verifies, it never invents a product.
type Retriever struct {
	names []string // display names
	keys  []string // lowercase match keys, same index as names
}

func NewRetriever(names []string) *Retriever {
	r := &Retriever{}
	seen := map[string]bool{}
	for _, n := range names {
		k := strings.ToLower(strings.TrimSpace(n))
		if seen[k] || !usableKey(k) {
			continue
		}
		seen[k] = true
		r.names = append(r.names, n)
		r.keys = append(r.keys, k)
	}
	return r
}

// usableKey drops keys too short to be meaningful evidence ("oa", "cms").
func usableKey(k string) bool {
	n := utf8.RuneCountInString(k)
	if n == len(k) { // ascii
		return n >= 4
	}
	return n >= 2
}

// containsWord matches ASCII keys on word boundaries ("acti" must not match
// "action"); CJK keys have no word boundaries and match as substrings.
func containsWord(haystack, key string) bool {
	if utf8.RuneCountInString(key) != len(key) {
		return strings.Contains(haystack, key)
	}
	for from := 0; ; {
		i := strings.Index(haystack[from:], key)
		if i < 0 {
			return false
		}
		start, end := from+i, from+i+len(key)
		if (start == 0 || !isWordByte(haystack[start-1])) && (end == len(haystack) || !isWordByte(haystack[end])) {
			return true
		}
		from = start + 1
	}
}

func isWordByte(b byte) bool {
	return b == '_' || b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

// Find returns up to max names occurring in haystack, longest match first.
func (r *Retriever) Find(haystack string, max int) []string {
	var hits []int
	for i, k := range r.keys {
		if containsWord(haystack, k) {
			hits = append(hits, i)
		}
	}
	sort.Slice(hits, func(a, b int) bool { return len(r.keys[hits[a]]) > len(r.keys[hits[b]]) })
	var out []string
	for _, i := range hits {
		out = append(out, r.names[i])
		if len(out) >= max {
			break
		}
	}
	return out
}
