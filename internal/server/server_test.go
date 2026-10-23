package server

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"dnsserver/internal/dns"
	"dnsserver/internal/resolver"
	"dnsserver/internal/zone"
)

// TestUDPAndTCP runs the real server on random local ports and queries it
// the way dig would: once over UDP and twice over one TCP connection.
func TestUDPAndTCP(t *testing.T) {
	z, err := zone.Load(strings.NewReader("$DOMAIN home.\nnas.home. 300 A 192.168.1.20\n"))
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := New(resolver.New(resolver.Config{}, z, nil, log), log)

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 2)
	go func() { done <- srv.ServeUDP(ctx, pc) }()
	go func() { done <- srv.ServeTCP(ctx, ln) }()

	query, _ := (&dns.Message{
		Header:    dns.Header{ID: 99, RecursionDesired: true},
		Questions: []dns.Question{{Name: "nas.home.", Type: dns.TypeA, Class: dns.ClassIN}},
	}).Pack()

	check := func(network string, resp []byte) {
		t.Helper()
		m, err := dns.Parse(resp)
		if err != nil {
			t.Fatalf("%s: %v", network, err)
		}
		if m.ID != 99 || len(m.Answers) != 1 {
			t.Fatalf("%s: ID=%d answers=%d", network, m.ID, len(m.Answers))
		}
		if ip, _ := netip.AddrFromSlice(m.Answers[0].Data); ip.String() != "192.168.1.20" {
			t.Fatalf("%s: got %s", network, ip)
		}
	}

	// UDP: one packet out, one packet back.
	uc, err := net.Dial("udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	uc.SetDeadline(time.Now().Add(2 * time.Second))
	uc.Write(query)
	buf := make([]byte, 65535)
	n, err := uc.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	check("udp", buf[:n])

	// TCP: length-prefixed messages, several per connection.
	tc, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer tc.Close()
	tc.SetDeadline(time.Now().Add(2 * time.Second))
	for range 2 {
		if err := dns.WriteTCP(tc, query); err != nil {
			t.Fatal(err)
		}
		resp, err := dns.ReadTCP(tc)
		if err != nil {
			t.Fatal(err)
		}
		check("tcp", resp)
	}

	// Shutdown must stop both servers, even with a TCP connection still open.
	cancel()
	for range 2 {
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("serve returned %v, want nil", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("server did not stop after cancel")
		}
	}
}
