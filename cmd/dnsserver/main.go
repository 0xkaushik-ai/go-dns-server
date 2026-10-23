// Command dnsserver runs a small DNS server: local records from a zone file,
// optional ad blocking, and forwarding with a cache for everything else.
//
// Usage:
//
//	go run ./cmd/dnsserver [-addr :1053] [-upstream 1.1.1.1:53] \
//	    [-zone examples/zones.txt] [-blocklist examples/blocklist.txt]
//
// Then query it with dig:
//
//	dig @127.0.0.1 -p 1053 nas.home
//
// Stop it with Ctrl+C. See README.md for details.
package main

import (
	"context"
	"flag"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"dnsserver/internal/blocklist"
	"dnsserver/internal/resolver"
	"dnsserver/internal/server"
	"dnsserver/internal/zone"
)

func main() {
	addr := flag.String("addr", ":1053", "address for both UDP and TCP (port 53 needs root)")
	upstream := flag.String("upstream", "1.1.1.1:53", "upstream resolver host:port (empty = answer local names only)")
	zonePath := flag.String("zone", "", "zone file with local records")
	blockPath := flag.String("blocklist", "", "file of domains to block")
	cacheSize := flag.Int("cache", 10000, "max cached responses (0 = no cache)")
	timeout := flag.Duration("timeout", 2*time.Second, "upstream timeout")
	debug := flag.Bool("debug", false, "log malformed queries too")
	flag.Parse()

	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level}))

	var z *zone.Zone
	if *zonePath != "" {
		var err error
		if z, err = zone.LoadFile(*zonePath); err != nil {
			log.Error("loading zone", "error", err)
			os.Exit(1)
		}
		log.Info("zone loaded", "file", *zonePath, "domains", z.Domains())
	}

	var bl *blocklist.List
	if *blockPath != "" {
		var err error
		if bl, err = blocklist.LoadFile(*blockPath); err != nil {
			log.Error("loading blocklist", "error", err)
			os.Exit(1)
		}
		log.Info("blocklist loaded", "file", *blockPath, "domains", bl.Len())
	}

	cfg := resolver.Config{Upstream: *upstream, Timeout: *timeout, CacheSize: *cacheSize}
	log.Info("resolver", "config", cfg.String())
	srv := server.New(resolver.New(cfg, z, bl, log), log)

	// DNS uses the same port number for UDP and TCP.
	pc, err := net.ListenPacket("udp", *addr)
	if err != nil {
		log.Error("listen udp", "error", err)
		os.Exit(1)
	}
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Error("listen tcp", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errc := make(chan error, 2)
	go func() { errc <- srv.ServeUDP(ctx, pc) }()
	go func() { errc <- srv.ServeTCP(ctx, ln) }()

	// Wait for both. If one fails, cancel the other.
	failed := false
	for range 2 {
		if err := <-errc; err != nil {
			log.Error("server failed", "error", err)
			failed = true
			stop()
		}
	}
	if failed {
		os.Exit(1)
	}
	log.Info("dns server stopped")
}
