package resolver

import (
	"encoding/binary"
	"slices"
	"sync"
	"time"

	"dnsserver/internal/dns"
)

const (
	// negativeTTL is how long "does not exist" answers are cached when the
	// upstream gives no SOA record to say otherwise.
	negativeTTL = 60 * time.Second
	// maxTTL caps how long anything is cached, whatever upstream says.
	maxTTL = 24 * time.Hour
)

// cacheKey identifies a question. Names are lower-cased because DNS names
// are case-insensitive.
type cacheKey struct {
	name   string
	qtype  uint16
	qclass uint16
}

// cacheEntry stores an upstream response as raw bytes, plus where its TTL
// fields are, so a hit can be served without re-encoding the message.
type cacheEntry struct {
	resp       []byte
	ttlOffsets []int
	stored     time.Time
	ttl        time.Duration
}

// Cache holds upstream responses until their TTL runs out. A nil *Cache
// caches nothing.
type Cache struct {
	mu      sync.Mutex
	max     int
	entries map[cacheKey]cacheEntry
}

// NewCache returns a cache holding at most max responses, or nil if max <= 0.
func NewCache(max int) *Cache {
	if max <= 0 {
		return nil
	}
	return &Cache{max: max, entries: make(map[cacheKey]cacheEntry)}
}

// Get returns a cached response re-labelled with the client's query ID and
// with every TTL lowered by the time spent in the cache. A client that sees
// "TTL 200" knows the record is good for 200 more seconds, not 300.
func (c *Cache) Get(key cacheKey, id uint16, now time.Time) ([]byte, bool) {
	if c == nil {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	e, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	age := now.Sub(e.stored)
	if age >= e.ttl {
		delete(c.entries, key)
		return nil, false
	}

	out := slices.Clone(e.resp)
	binary.BigEndian.PutUint16(out, id)
	elapsed := uint32(age / time.Second)
	for _, off := range e.ttlOffsets {
		ttl := binary.BigEndian.Uint32(e.resp[off:])
		binary.BigEndian.PutUint32(out[off:], ttl-min(ttl, elapsed))
	}
	return out, true
}

// Put stores resp (already parsed as m) if it is cacheable.
func (c *Cache) Put(key cacheKey, resp []byte, m *dns.Message, now time.Time) {
	if c == nil || m.Truncated || (m.RCode != dns.RCodeSuccess && m.RCode != dns.RCodeNXDomain) {
		return
	}
	ttl, offsets := cacheTTL(m)
	if ttl <= 0 {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= c.max {
		c.evict(now)
	}
	c.entries[key] = cacheEntry{resp: slices.Clone(resp), ttlOffsets: offsets, stored: now, ttl: ttl}
}

// Len returns the number of cached responses.
func (c *Cache) Len() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// evict makes room: first drop expired entries, then, if still full, drop
// one arbitrary entry (Go's random map order makes this random eviction).
func (c *Cache) evict(now time.Time) {
	for k, e := range c.entries {
		if now.Sub(e.stored) >= e.ttl {
			delete(c.entries, k)
		}
	}
	for k := range c.entries {
		if len(c.entries) < c.max {
			break
		}
		delete(c.entries, k)
	}
}

// cacheTTL decides how long m may be cached and finds its TTL fields.
//
// Positive answers live as long as their shortest record TTL. Negative
// answers (NXDOMAIN, or NOERROR with no answers) live as long as the SOA
// record in the authority section says: the smaller of its own TTL and
// its MINIMUM field (RFC 2308).
func cacheTTL(m *dns.Message) (time.Duration, []int) {
	var offsets []int
	shortest := ^uint32(0)
	for _, sec := range [][]dns.Record{m.Answers, m.Authority, m.Additional} {
		for _, rr := range sec {
			if rr.Type == dns.TypeOPT {
				continue // the OPT "TTL" field holds EDNS flags, not a TTL
			}
			offsets = append(offsets, rr.TTLOffset)
			shortest = min(shortest, rr.TTL)
		}
	}

	ttl := time.Duration(shortest) * time.Second
	if m.RCode == dns.RCodeNXDomain || len(m.Answers) == 0 {
		ttl = negativeTTL
		for _, rr := range m.Authority {
			// SOA MINIMUM is the last 4 bytes of the SOA data, whatever the
			// (possibly compressed) names before it look like.
			if rr.Type == dns.TypeSOA && len(rr.Data) >= 4 {
				soaMin := binary.BigEndian.Uint32(rr.Data[len(rr.Data)-4:])
				ttl = time.Duration(min(rr.TTL, soaMin)) * time.Second
			}
		}
	}
	return min(ttl, maxTTL), offsets
}
