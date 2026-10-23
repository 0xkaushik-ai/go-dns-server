package zone

import (
	"strings"
	"testing"

	"dnsserver/internal/dns"
)

const sample = `
# test zone
$DOMAIN home.
nas.home.     300 A     192.168.1.20
NAS.home      300 AAAA  fd00::20
files.home.   60  CNAME nas.home.
home.         300 MX    10 mail.home.
home.         300 TXT   "hello world"
a.deep.home.  300 A     10.0.0.1
`

func TestLoadAndLookup(t *testing.T) {
	z, err := Load(strings.NewReader(sample))
	if err != nil {
		t.Fatal(err)
	}

	rrs, exists := z.Lookup("Nas.Home.")
	if !exists || len(rrs) != 2 || rrs[0].Type != dns.TypeA || rrs[1].Type != dns.TypeAAAA {
		t.Fatalf("nas.home: exists=%v records=%+v", exists, rrs)
	}
	if target, ok := z.CNAME("files.home"); !ok || target != "nas.home." {
		t.Fatalf("CNAME(files.home) = %q, %v", target, ok)
	}
	// "deep.home." has no records but a child does: it exists (NODATA, not NXDOMAIN).
	if rrs, exists := z.Lookup("deep.home."); !exists || len(rrs) != 0 {
		t.Fatalf("deep.home: exists=%v records=%d, want exists with none", exists, len(rrs))
	}
	if _, exists := z.Lookup("missing.home."); exists {
		t.Fatal("missing.home should not exist")
	}

	for name, want := range map[string]bool{
		"home.": true, "x.y.home.": true, "HOME": true,
		"example.com.": false, "myhome.": false, // suffix must match a whole label
	} {
		if got := z.Authoritative(name); got != want {
			t.Errorf("Authoritative(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestLoadErrors(t *testing.T) {
	tests := map[string]string{
		"outside domain": "$DOMAIN home.\nexample.com. 300 A 1.2.3.4",
		"no domain":      "nas.home. 300 A 1.2.3.4",
		"bad ttl":        "$DOMAIN home.\nnas.home. -5 A 1.2.3.4",
		"bad ip":         "$DOMAIN home.\nnas.home. 300 A 999.1.1.1",
		"ipv6 in A":      "$DOMAIN home.\nnas.home. 300 A ::1",
		"ipv4 in AAAA":   "$DOMAIN home.\nnas.home. 300 AAAA 1.2.3.4",
		"cname conflict": "$DOMAIN home.\nnas.home. 300 CNAME x.home.\nnas.home. 300 A 1.2.3.4",
		"unknown type":   "$DOMAIN home.\nnas.home. 300 SRV x",
		"missing value":  "$DOMAIN home.\nnas.home. 300 A",
		"root domain":    "$DOMAIN .",
	}
	for name, input := range tests {
		if _, err := Load(strings.NewReader(input)); err == nil {
			t.Errorf("%s: Load succeeded, want error", name)
		}
	}
}

func TestNilZone(t *testing.T) {
	var z *Zone
	if z.Authoritative("home.") {
		t.Error("nil zone should not be authoritative")
	}
	if _, exists := z.Lookup("home."); exists {
		t.Error("nil zone should have no names")
	}
}
