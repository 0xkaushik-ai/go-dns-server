// Package blocklist decides which domains to block, Pi-hole style.
//
// Blocking a domain also blocks every subdomain: blocking "ads.example.com"
// blocks "x.ads.example.com" too, but not "example.com".
//
// Two line formats are accepted, so you can reuse public hosts-file lists:
//
//	ads.example.com
//	0.0.0.0 tracker.example.net
//
// Blank lines and lines starting with '#' are ignored.
package blocklist

import (
	"bufio"
	"io"
	"net/netip"
	"os"
	"strings"
)

// List is a set of blocked domains. A nil *List blocks nothing.
type List struct {
	domains map[string]struct{}
}

// LoadFile reads a blocklist from disk.
func LoadFile(path string) (*List, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Load(f)
}

// Load parses a blocklist.
func Load(r io.Reader) (*List, error) {
	l := &List{domains: make(map[string]struct{})}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 0 || strings.HasPrefix(f[0], "#") {
			continue
		}
		domain := f[0]
		// Hosts-file format: "<ip> <domain>".
		if _, err := netip.ParseAddr(f[0]); err == nil {
			if len(f) < 2 {
				continue
			}
			domain = f[1]
		}
		l.domains[canonical(domain)] = struct{}{}
	}
	return l, sc.Err()
}

// Blocked reports whether name or any of its parent domains is listed.
func (l *List) Blocked(name string) bool {
	if l == nil {
		return false
	}
	// Walk up the name: a.b.c. -> b.c. -> c.
	for n := canonical(name); n != "" && n != "."; {
		if _, ok := l.domains[n]; ok {
			return true
		}
		i := strings.IndexByte(n, '.')
		n = n[i+1:]
	}
	return false
}

// Len returns how many domains are listed.
func (l *List) Len() int {
	if l == nil {
		return 0
	}
	return len(l.domains)
}

func canonical(name string) string {
	name = strings.ToLower(name)
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	return name
}
