// Package resolver decides how to answer each DNS query.
//
// For every query, in order:
//
//  1. blocked domain?              -> NXDOMAIN                ("blocked")
//  2. inside a local zone domain?  -> answer from the zone    ("local")
//  3. answer in the cache?         -> serve it, TTLs lowered  ("cache")
//  4. otherwise                    -> ask the upstream server ("upstream")
package resolver

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"strings"
	"time"

	"dnsserver/internal/blocklist"
	"dnsserver/internal/dns"
	"dnsserver/internal/zone"
)

// maxCNAMEChain bounds how many local CNAMEs are followed, so a loop such as
// a -> b -> a cannot spin forever.
const maxCNAMEChain = 8

// Config configures a Resolver.
type Config struct {
	Upstream  string        // "host:port" of the upstream resolver; "" disables forwarding
	Timeout   time.Duration // how long to wait for the upstream
	CacheSize int           // max cached responses; 0 disables the cache
}

// Resolver answers DNS queries. It is safe for concurrent use.
type Resolver struct {
	cfg   Config
	zone  *zone.Zone
	block *blocklist.List
	cache *Cache
	log   *slog.Logger
	now   func() time.Time // replaceable in tests
}

// New creates a Resolver. z and bl may be nil.
func New(cfg Config, z *zone.Zone, bl *blocklist.List, log *slog.Logger) *Resolver {
	return &Resolver{
		cfg:   cfg,
		zone:  z,
		block: bl,
		cache: NewCache(cfg.CacheSize),
		log:   log,
		now:   time.Now,
	}
}

// Resolve answers one raw DNS query and returns the raw response, or nil if
// nothing should be sent back. network is "udp" or "tcp" (it controls
// truncation and how the upstream is contacted); client is for logging.
func (r *Resolver) Resolve(ctx context.Context, query []byte, network, client string) []byte {
	start := time.Now()

	q, err := dns.Parse(query)
	if err != nil {
		// Answer FORMERR only if the bytes at least look like a query. Never
		// reply to responses: that is how reflection loops start.
		if len(query) < dns.HeaderLen || query[2]&0x80 != 0 {
			return nil
		}
		r.log.Debug("malformed query", "client", client, "error", err)
		return pack(&dns.Message{Header: dns.Header{
			ID: binary.BigEndian.Uint16(query), Response: true, RCode: dns.RCodeFormErr,
		}})
	}
	if q.Response {
		return nil
	}

	resp, source := r.answer(ctx, q, query, network)
	if resp == nil {
		return nil
	}
	if network == "udp" && len(resp) > maxUDPSize(q) {
		resp = truncated(q)
	}

	if len(q.Questions) == 1 {
		qu := q.Questions[0]
		r.log.Info("query",
			"client", client, "net", network,
			"name", qu.Name, "type", dns.TypeString(qu.Type),
			"source", source, "rcode", dns.RCodeString(resp[3]&0xF),
			"duration", time.Since(start).Round(time.Microsecond))
	}
	return resp
}

// answer picks the source of the answer and returns it with a label for logs.
func (r *Resolver) answer(ctx context.Context, q *dns.Message, raw []byte, network string) ([]byte, string) {
	if q.Opcode != 0 {
		return reply(q, dns.RCodeNotImp), "error" // only standard queries
	}
	if len(q.Questions) != 1 {
		return reply(q, dns.RCodeFormErr), "error" // in practice always exactly one
	}
	qu := q.Questions[0]

	switch {
	case qu.Class != dns.ClassIN:
		return reply(q, dns.RCodeNotImp), "error"
	case r.block.Blocked(qu.Name):
		return reply(q, dns.RCodeNXDomain), "blocked"
	case r.zone.Authoritative(qu.Name):
		return r.local(q), "local"
	case r.cfg.Upstream == "":
		return reply(q, dns.RCodeRefused), "refused"
	default:
		return r.forward(ctx, q, raw, network)
	}
}

// local answers from the zone, following CNAMEs inside the zone.
//
// Outcomes: records found (NOERROR + answers), name exists but has no
// records of that type (NOERROR, empty: "NODATA"), or name does not exist
// (NXDOMAIN). The AA flag is set because we are the authority.
func (r *Resolver) local(q *dns.Message) []byte {
	m := dns.NewReply(q, dns.RCodeSuccess)
	m.Authoritative = true
	qtype := q.Questions[0].Type
	name := q.Questions[0].Name

	for range maxCNAMEChain {
		if !r.zone.Authoritative(name) {
			break // the alias points outside our zone; the client resolves it
		}
		records, exists := r.zone.Lookup(name)
		if !exists {
			m.RCode = dns.RCodeNXDomain
			break
		}

		var matched []dns.Record
		for _, rr := range records {
			if rr.Type == qtype || qtype == dns.TypeANY {
				matched = append(matched, rr)
			}
		}
		if len(matched) > 0 {
			m.Answers = append(m.Answers, matched...)
			break
		}

		target, isAlias := r.zone.CNAME(name)
		if !isAlias {
			break // NODATA
		}
		m.Answers = append(m.Answers, records[0]) // the CNAME record itself
		name = target
	}
	return pack(m)
}

// forward serves the query from the cache or the upstream resolver.
func (r *Resolver) forward(ctx context.Context, q *dns.Message, raw []byte, network string) ([]byte, string) {
	qu := q.Questions[0]
	key := cacheKey{name: strings.ToLower(qu.Name), qtype: qu.Type, qclass: qu.Class}

	if resp, ok := r.cache.Get(key, q.ID, r.now()); ok {
		return resp, "cache"
	}

	resp, err := exchange(ctx, network, r.cfg.Upstream, raw, r.cfg.Timeout)
	if err != nil {
		r.log.Warn("upstream failed", "upstream", r.cfg.Upstream, "name", qu.Name, "error", err)
		return reply(q, dns.RCodeServFail), "error"
	}

	m, err := dns.Parse(resp)
	if err != nil || !m.Response || len(m.Questions) != 1 || !sameQuestion(m.Questions[0], qu) {
		r.log.Warn("bad upstream response", "upstream", r.cfg.Upstream, "name", qu.Name)
		return reply(q, dns.RCodeServFail), "error"
	}
	r.cache.Put(key, resp, m, r.now())
	return resp, "upstream"
}

// exchange sends query to the upstream and returns its response.
//
// The query goes out with a fresh random ID (and, over UDP, a fresh random
// source port from a new socket). An attacker trying to inject a forged
// answer must guess both, which is the defence against cache-poisoning
// attacks like the 2008 Kaminsky attack.
func exchange(ctx context.Context, network, upstream string, query []byte, timeout time.Duration) ([]byte, error) {
	clientID := binary.BigEndian.Uint16(query)
	var idBytes [2]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		return nil, err
	}
	id := binary.BigEndian.Uint16(idBytes[:])
	out := slices.Clone(query)
	binary.BigEndian.PutUint16(out, id)

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, network, upstream)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	conn.SetDeadline(deadline)

	var resp []byte
	if network == "tcp" {
		if err := dns.WriteTCP(conn, out); err != nil {
			return nil, err
		}
		if resp, err = dns.ReadTCP(conn); err != nil {
			return nil, err
		}
		if binary.BigEndian.Uint16(resp) != id {
			return nil, errors.New("response ID does not match query")
		}
	} else {
		if _, err := conn.Write(out); err != nil {
			return nil, err
		}
		buf := make([]byte, 65535)
		for resp == nil {
			n, err := conn.Read(buf)
			if err != nil {
				return nil, err
			}
			// Skip packets with the wrong ID (stale or forged) and keep
			// waiting for the real answer until the deadline.
			if n >= dns.HeaderLen && binary.BigEndian.Uint16(buf) == id {
				resp = slices.Clone(buf[:n])
			}
		}
	}

	binary.BigEndian.PutUint16(resp, clientID) // give the client back its own ID
	return resp, nil
}

// maxUDPSize is the largest UDP response the client accepts: 512 bytes, or
// the size it advertised in an EDNS(0) OPT record (the OPT "class" field).
func maxUDPSize(q *dns.Message) int {
	for _, rr := range q.Additional {
		if rr.Type == dns.TypeOPT {
			return max(int(rr.Class), dns.MaxUDPSize)
		}
	}
	return dns.MaxUDPSize
}

// truncated returns an empty response with the TC flag set, which tells the
// client "too big for UDP, ask again over TCP".
func truncated(q *dns.Message) []byte {
	m := dns.NewReply(q, dns.RCodeSuccess)
	m.Truncated = true
	return pack(m)
}

func reply(q *dns.Message, rcode uint8) []byte {
	return pack(dns.NewReply(q, rcode))
}

// pack encodes m. It returns nil (send nothing) in the rare case that a
// name from the query cannot be re-encoded.
func pack(m *dns.Message) []byte {
	b, err := m.Pack()
	if err != nil {
		return nil
	}
	return b
}

func sameQuestion(a, b dns.Question) bool {
	return strings.EqualFold(a.Name, b.Name) && a.Type == b.Type && a.Class == b.Class
}

// String describes the configuration for the startup log.
func (c Config) String() string {
	up := c.Upstream
	if up == "" {
		up = "none"
	}
	return fmt.Sprintf("upstream=%s timeout=%s cache=%d", up, c.Timeout, c.CacheSize)
}
