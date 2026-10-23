// Package server receives DNS queries over UDP and TCP and hands them to a
// Resolver.
//
// DNS normally uses UDP: one packet per query and per answer. TCP is used
// when an answer is too big for UDP (the client retries after seeing the TC
// flag) and for zone transfers. Over TCP each message is prefixed with its
// 2-byte length, and one connection may carry several queries.
package server

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"slices"
	"sync"
	"time"

	"dnsserver/internal/dns"
)

const (
	maxInFlight    = 512              // UDP queries resolved at once; extras are dropped
	maxTCPConns    = 128              // TCP connections at once; extras are closed
	tcpIdleTimeout = 10 * time.Second // close idle TCP connections (RFC 7766 suggests seconds)
)

// Resolver turns a raw query into a raw response (nil = send nothing).
type Resolver interface {
	Resolve(ctx context.Context, query []byte, network, client string) []byte
}

// Server serves DNS over UDP and TCP.
type Server struct {
	res    Resolver
	log    *slog.Logger
	udpSem chan struct{}
	tcpSem chan struct{}
	wg     sync.WaitGroup
}

// New returns a Server that answers with res.
func New(res Resolver, log *slog.Logger) *Server {
	return &Server{
		res:    res,
		log:    log,
		udpSem: make(chan struct{}, maxInFlight),
		tcpSem: make(chan struct{}, maxTCPConns),
	}
}

// ServeUDP answers queries on conn until ctx is cancelled. Each query is
// resolved in its own goroutine, because forwarding to an upstream server
// can take a while and must not hold up other clients.
func (s *Server) ServeUDP(ctx context.Context, conn net.PacketConn) error {
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	defer s.wg.Wait()

	s.log.Info("listening", "net", "udp", "addr", conn.LocalAddr())
	buf := make([]byte, 65535)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			continue // e.g. an ICMP error from an earlier reply; keep serving
		}

		// The buffer is reused by the next ReadFrom, so the goroutine gets a copy.
		query := slices.Clone(buf[:n])

		select {
		case s.udpSem <- struct{}{}:
		default:
			s.log.Warn("too many queries in flight, dropping", "client", addr)
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() { <-s.udpSem }()
			if resp := s.res.Resolve(ctx, query, "udp", addr.String()); resp != nil {
				conn.WriteTo(resp, addr)
			}
		}()
	}
}

// ServeTCP answers queries on connections from ln until ctx is cancelled.
func (s *Server) ServeTCP(ctx context.Context, ln net.Listener) error {
	stop := context.AfterFunc(ctx, func() { ln.Close() })
	defer stop()
	defer s.wg.Wait()

	s.log.Info("listening", "net", "tcp", "addr", ln.Addr())
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			s.log.Warn("accept failed", "error", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}

		select {
		case s.tcpSem <- struct{}{}:
		default:
			s.log.Warn("too many TCP connections, closing", "client", conn.RemoteAddr())
			conn.Close()
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() { <-s.tcpSem }()
			s.handleTCP(ctx, conn)
		}()
	}
}

// handleTCP answers queries on one connection until the client closes it,
// it stays idle too long, or the server shuts down.
func (s *Server) handleTCP(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	client := conn.RemoteAddr().String()
	for {
		conn.SetReadDeadline(time.Now().Add(tcpIdleTimeout))
		query, err := dns.ReadTCP(conn)
		if err != nil {
			return // EOF, idle timeout, or garbage length: just hang up
		}
		resp := s.res.Resolve(ctx, query, "tcp", client)
		if resp == nil {
			return
		}
		conn.SetWriteDeadline(time.Now().Add(tcpIdleTimeout))
		if err := dns.WriteTCP(conn, resp); err != nil {
			return
		}
	}
}
