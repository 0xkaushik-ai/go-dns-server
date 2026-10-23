package resolver

import (
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"dnsserver/internal/blocklist"
	"dnsserver/internal/dns"
	"dnsserver/internal/zone"
)

const testZone = `
$DOMAIN home.
nas.home.    300 A     192.168.1.20
files.home.  60  CNAME nas.home.
loop1.home.  60  CNAME loop2.home.
loop2.home.  60  CNAME loop1.home.
out.home.    60  CNAME example.com.
big.home.    60  TXT   ` + "BIG" + `
a.deep.home. 300 A     10.0.0.1
`

// fakeUpstream is a UDP DNS server that answers every A query with
// 93.184.216.34 (TTL 300) and counts how many queries it got.
type fakeUpstream struct {
	addr    string
	queries atomic.Int32
}

func startUpstream(t *testing.T) *fakeUpstream {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	up := &fakeUpstream{addr: conn.LocalAddr().String()}

	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			up.queries.Add(1)
			q, err := dns.Parse(buf[:n])
			if err != nil {
				continue
			}
			m := dns.NewReply(q, dns.RCodeSuccess)
			m.Answers = []dns.Record{{
				Name: q.Questions[0].Name, Type: dns.TypeA, Class: dns.ClassIN, TTL: 300,
				Data: dns.AData(netip.MustParseAddr("93.184.216.34")),
			}}
			b, _ := m.Pack()
			conn.WriteTo(b, addr)
		}
	}()
	return up
}

// clock is a fake time source the test can move forward.
type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newResolver(t *testing.T, upstream string) (*Resolver, *clock) {
	t.Helper()
	// A TXT record big enough to overflow a 512-byte UDP response.
	z, err := zone.Load(strings.NewReader(strings.Replace(testZone, "BIG", strings.Repeat("x", 700), 1)))
	if err != nil {
		t.Fatal(err)
	}
	bl, _ := blocklist.Load(strings.NewReader("ads.example.com\n"))
	r := New(Config{Upstream: upstream, Timeout: time.Second, CacheSize: 100},
		z, bl, slog.New(slog.NewTextHandler(io.Discard, nil)))
	c := &clock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	r.now = c.now
	return r, c
}

// ask builds a query, resolves it and parses the response.
func ask(t *testing.T, r *Resolver, network, name string, qtype uint16) *dns.Message {
	t.Helper()
	q := &dns.Message{
		Header:    dns.Header{ID: 4242, RecursionDesired: true},
		Questions: []dns.Question{{Name: name, Type: qtype, Class: dns.ClassIN}},
	}
	raw, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	resp := r.Resolve(context.Background(), raw, network, "test")
	if resp == nil {
		t.Fatalf("no response for %s", name)
	}
	m, err := dns.Parse(resp)
	if err != nil {
		t.Fatal(err)
	}
	if m.ID != 4242 || !m.Response {
		t.Fatalf("response ID=%d QR=%v, want 4242 true", m.ID, m.Response)
	}
	return m
}

func ipOf(t *testing.T, rr dns.Record) string {
	t.Helper()
	ip, ok := netip.AddrFromSlice(rr.Data)
	if !ok {
		t.Fatalf("record data %v is not an IP", rr.Data)
	}
	return ip.String()
}

func TestLocalAnswers(t *testing.T) {
	r, _ := newResolver(t, "")

	m := ask(t, r, "udp", "NAS.home.", dns.TypeA)
	if m.RCode != dns.RCodeSuccess || !m.Authoritative || len(m.Answers) != 1 || ipOf(t, m.Answers[0]) != "192.168.1.20" {
		t.Fatalf("nas.home A: %+v", m)
	}

	// CNAME is followed inside the zone: answer = CNAME + A.
	m = ask(t, r, "udp", "files.home.", dns.TypeA)
	if len(m.Answers) != 2 || m.Answers[0].Type != dns.TypeCNAME || ipOf(t, m.Answers[1]) != "192.168.1.20" {
		t.Fatalf("files.home A: %+v", m.Answers)
	}

	// A CNAME loop stops after maxCNAMEChain steps instead of hanging.
	if m = ask(t, r, "udp", "loop1.home.", dns.TypeA); len(m.Answers) != maxCNAMEChain {
		t.Fatalf("loop: got %d answers, want %d", len(m.Answers), maxCNAMEChain)
	}

	// A CNAME pointing outside the zone is returned as-is.
	if m = ask(t, r, "udp", "out.home.", dns.TypeA); len(m.Answers) != 1 || m.Answers[0].Type != dns.TypeCNAME {
		t.Fatalf("out.home: %+v", m.Answers)
	}

	if m = ask(t, r, "udp", "nope.home.", dns.TypeA); m.RCode != dns.RCodeNXDomain || !m.Authoritative {
		t.Fatalf("nope.home: rcode %s, want NXDOMAIN", dns.RCodeString(m.RCode))
	}

	// Name exists but has no AAAA record: NODATA (NOERROR, no answers).
	if m = ask(t, r, "udp", "nas.home.", dns.TypeAAAA); m.RCode != dns.RCodeSuccess || len(m.Answers) != 0 {
		t.Fatalf("nas.home AAAA: %+v", m)
	}
	// Empty non-terminal: also NODATA.
	if m = ask(t, r, "udp", "deep.home.", dns.TypeA); m.RCode != dns.RCodeSuccess {
		t.Fatalf("deep.home: rcode %s, want NOERROR", dns.RCodeString(m.RCode))
	}
}

func TestBlockedAndRefused(t *testing.T) {
	r, _ := newResolver(t, "")
	if m := ask(t, r, "udp", "x.ads.example.com.", dns.TypeA); m.RCode != dns.RCodeNXDomain {
		t.Fatalf("blocked: rcode %s, want NXDOMAIN", dns.RCodeString(m.RCode))
	}
	// No upstream configured: names outside the zone are refused.
	if m := ask(t, r, "udp", "example.com.", dns.TypeA); m.RCode != dns.RCodeRefused {
		t.Fatalf("no upstream: rcode %s, want REFUSED", dns.RCodeString(m.RCode))
	}
}

func TestForwardAndCache(t *testing.T) {
	up := startUpstream(t)
	r, clk := newResolver(t, up.addr)

	m := ask(t, r, "udp", "example.com.", dns.TypeA)
	if len(m.Answers) != 1 || ipOf(t, m.Answers[0]) != "93.184.216.34" || m.Answers[0].TTL != 300 {
		t.Fatalf("forwarded answer: %+v", m.Answers)
	}

	// 100 seconds later: served from cache with the TTL lowered to 200.
	clk.t = clk.t.Add(100 * time.Second)
	m = ask(t, r, "udp", "EXAMPLE.com.", dns.TypeA)
	if m.Answers[0].TTL != 200 {
		t.Fatalf("cached TTL = %d, want 200", m.Answers[0].TTL)
	}
	if n := up.queries.Load(); n != 1 {
		t.Fatalf("upstream got %d queries, want 1 (second should be cached)", n)
	}

	// After the TTL runs out the upstream is asked again.
	clk.t = clk.t.Add(201 * time.Second)
	ask(t, r, "udp", "example.com.", dns.TypeA)
	if n := up.queries.Load(); n != 2 {
		t.Fatalf("upstream got %d queries, want 2 after expiry", n)
	}
}

func TestUpstreamDown(t *testing.T) {
	// Reserve a port, then free it so nothing is listening there.
	conn, _ := net.ListenPacket("udp", "127.0.0.1:0")
	addr := conn.LocalAddr().String()
	conn.Close()

	r, _ := newResolver(t, addr)
	if m := ask(t, r, "udp", "example.com.", dns.TypeA); m.RCode != dns.RCodeServFail {
		t.Fatalf("rcode %s, want SERVFAIL", dns.RCodeString(m.RCode))
	}
}

func TestTruncation(t *testing.T) {
	r, _ := newResolver(t, "")

	// Over UDP the ~750-byte answer does not fit in 512 bytes: TC is set.
	if m := ask(t, r, "udp", "big.home.", dns.TypeTXT); !m.Truncated || len(m.Answers) != 0 {
		t.Fatalf("udp: TC=%v answers=%d, want truncated and empty", m.Truncated, len(m.Answers))
	}
	// Over TCP there is no such limit.
	if m := ask(t, r, "tcp", "big.home.", dns.TypeTXT); m.Truncated || len(m.Answers) != 1 {
		t.Fatalf("tcp: TC=%v answers=%d, want full answer", m.Truncated, len(m.Answers))
	}
}

func TestBadInput(t *testing.T) {
	r, _ := newResolver(t, "")
	ctx := context.Background()

	if resp := r.Resolve(ctx, []byte{1, 2, 3}, "udp", "test"); resp != nil {
		t.Error("a packet shorter than a header should get no reply")
	}

	// A header claiming one question, with no question: FORMERR.
	bad := []byte{0, 7, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	if resp := r.Resolve(ctx, bad, "udp", "test"); resp == nil || resp[3]&0xF != dns.RCodeFormErr {
		t.Errorf("malformed query: got %v, want FORMERR", resp)
	}

	// The same bytes with QR=1 are a response: never answered.
	bad[2] |= 0x80
	if resp := r.Resolve(ctx, bad, "udp", "test"); resp != nil {
		t.Error("responses must not be answered")
	}

	// Opcode 2 (STATUS) is not implemented.
	q := &dns.Message{Header: dns.Header{ID: 1, Opcode: 2},
		Questions: []dns.Question{{Name: "nas.home.", Type: dns.TypeA, Class: dns.ClassIN}}}
	raw, _ := q.Pack()
	if resp := r.Resolve(ctx, raw, "udp", "test"); resp[3]&0xF != dns.RCodeNotImp {
		t.Errorf("opcode 2: rcode %d, want NOTIMP", resp[3]&0xF)
	}
}

func TestCacheNegativeTTLFromSOA(t *testing.T) {
	// NXDOMAIN with an SOA whose TTL is 900 and MINIMUM is 120:
	// the answer may be cached for min(900, 120) = 120 seconds.
	soa := make([]byte, 22) // two root names + 5 uint32 fields
	binary.BigEndian.PutUint32(soa[18:], 120)
	m := &dns.Message{
		Header:    dns.Header{Response: true, RCode: dns.RCodeNXDomain},
		Authority: []dns.Record{{Name: "com.", Type: dns.TypeSOA, Class: dns.ClassIN, TTL: 900, Data: soa}},
	}
	if ttl, _ := cacheTTL(m); ttl != 120*time.Second {
		t.Fatalf("negative TTL = %s, want 2m0s", ttl)
	}
}
