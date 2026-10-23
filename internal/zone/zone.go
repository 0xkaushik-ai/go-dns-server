// Package zone holds the DNS records this server answers for itself
// ("authoritatively"), loaded from a simple text file.
//
// File format, one entry per line ('#' starts a comment line):
//
//	$DOMAIN home.                          # we are the authority for home. and below
//	nas.home.        300  A      192.168.1.20
//	nas.home.        300  AAAA   fd00::20
//	files.home.      300  CNAME  nas.home.
//	home.            300  MX     10 mail.home.
//	home.            300  TXT    "hello from my home network"
//
// Columns: name, TTL in seconds, type, value. Names are case-insensitive and
// the trailing dot is optional. Every record must sit under a $DOMAIN.
package zone

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"dnsserver/internal/dns"
)

// Zone is a read-only set of local records. A nil *Zone is valid and empty.
type Zone struct {
	domains []string                // authoritative domains, e.g. "home."
	records map[string][]dns.Record // name -> records
	cnames  map[string]string       // name -> CNAME target
	names   map[string]bool         // every existing name, including empty parents
}

// LoadFile reads a zone file from disk.
func LoadFile(path string) (*Zone, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Load(f)
}

// Load parses a zone file. See the package comment for the format.
func Load(r io.Reader) (*Zone, error) {
	z := &Zone{
		records: make(map[string][]dns.Record),
		cnames:  make(map[string]string),
		names:   make(map[string]bool),
	}

	sc := bufio.NewScanner(r)
	for lineNo := 1; sc.Scan(); lineNo++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if err := z.parseLine(line); err != nil {
			return nil, fmt.Errorf("zone line %d: %w", lineNo, err)
		}
	}
	return z, sc.Err()
}

func (z *Zone) parseLine(line string) error {
	f := strings.Fields(line)

	if f[0] == "$DOMAIN" {
		if len(f) != 2 || Canonical(f[1]) == "." {
			return fmt.Errorf("want: $DOMAIN <domain>")
		}
		d := Canonical(f[1])
		z.domains = append(z.domains, d)
		z.names[d] = true
		return nil
	}

	if len(f) < 4 {
		return fmt.Errorf("want: <name> <ttl> <type> <value>")
	}
	name := Canonical(f[0])
	if !z.Authoritative(name) {
		return fmt.Errorf("%s is not under any $DOMAIN", name)
	}
	ttl, err := strconv.ParseUint(f[1], 10, 32)
	if err != nil {
		return fmt.Errorf("bad TTL %q", f[1])
	}
	rr := dns.Record{Name: name, Class: dns.ClassIN, TTL: uint32(ttl)}
	value := f[3:]

	switch typ := strings.ToUpper(f[2]); typ {
	case "A", "AAAA":
		ip, err := netip.ParseAddr(value[0])
		if err != nil || len(value) != 1 {
			return fmt.Errorf("bad %s address %q", typ, strings.Join(value, " "))
		}
		if typ == "A" {
			if !ip.Is4() {
				return fmt.Errorf("A record needs an IPv4 address, got %s", ip)
			}
			rr.Type, rr.Data = dns.TypeA, dns.AData(ip)
		} else {
			if !ip.Is6() || ip.Is4In6() {
				return fmt.Errorf("AAAA record needs an IPv6 address, got %s", ip)
			}
			rr.Type, rr.Data = dns.TypeAAAA, dns.AAAAData(ip)
		}

	case "CNAME":
		if len(value) != 1 {
			return fmt.Errorf("want: CNAME <target>")
		}
		target := Canonical(value[0])
		if rr.Data, err = dns.NameData(target); err != nil {
			return err
		}
		rr.Type = dns.TypeCNAME
		z.cnames[name] = target

	case "MX":
		if len(value) != 2 {
			return fmt.Errorf("want: MX <preference> <host>")
		}
		pref, err := strconv.ParseUint(value[0], 10, 16)
		if err != nil {
			return fmt.Errorf("bad MX preference %q", value[0])
		}
		if rr.Data, err = dns.MXData(uint16(pref), Canonical(value[1])); err != nil {
			return err
		}
		rr.Type = dns.TypeMX

	case "TXT":
		rr.Type, rr.Data = dns.TypeTXT, dns.TXTData(strings.Trim(strings.Join(value, " "), `"`))

	default:
		return fmt.Errorf("unsupported type %q (want A, AAAA, CNAME, MX or TXT)", f[2])
	}

	// A CNAME means "this name is really that other name", so it cannot
	// share a name with any other record (RFC 1034 3.6.2).
	existing := z.records[name]
	if _, isAlias := z.cnames[name]; isAlias && len(existing) > 0 {
		return fmt.Errorf("%s has a CNAME and other records; a CNAME must be alone", name)
	}

	z.records[name] = append(existing, rr)
	// Mark the name and all its parents as existing, so a query for
	// "home." when only "nas.home." has records gets NODATA, not NXDOMAIN.
	for n := name; z.Authoritative(n); n = parent(n) {
		z.names[n] = true
	}
	return nil
}

// Authoritative reports whether name is inside one of the zone's domains.
func (z *Zone) Authoritative(name string) bool {
	if z == nil {
		return false
	}
	name = Canonical(name)
	for _, d := range z.domains {
		if name == d || strings.HasSuffix(name, "."+d) {
			return true
		}
	}
	return false
}

// Lookup returns the records for name and whether the name exists at all.
// A name can exist with no records of its own (an "empty non-terminal").
func (z *Zone) Lookup(name string) ([]dns.Record, bool) {
	if z == nil {
		return nil, false
	}
	name = Canonical(name)
	return z.records[name], z.names[name]
}

// CNAME returns the alias target of name, if it has one.
func (z *Zone) CNAME(name string) (string, bool) {
	if z == nil {
		return "", false
	}
	target, ok := z.cnames[Canonical(name)]
	return target, ok
}

// Domains returns the authoritative domains.
func (z *Zone) Domains() []string {
	if z == nil {
		return nil
	}
	return z.domains
}

// Canonical lower-cases name and adds the trailing dot.
func Canonical(name string) string {
	name = strings.ToLower(name)
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	return name
}

// parent returns the name one label up: "a.b.c." -> "b.c.", "c." -> ".".
func parent(name string) string {
	if i := strings.IndexByte(name, '.'); i >= 0 && i < len(name)-1 {
		return name[i+1:]
	}
	return "."
}
