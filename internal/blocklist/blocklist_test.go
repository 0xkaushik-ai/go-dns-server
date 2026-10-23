package blocklist

import (
	"strings"
	"testing"
)

func TestBlocked(t *testing.T) {
	l, err := Load(strings.NewReader(`
# comment
ads.example.com
0.0.0.0 Tracker.Net
127.0.0.1
`))
	if err != nil {
		t.Fatal(err)
	}
	if l.Len() != 2 {
		t.Fatalf("Len = %d, want 2", l.Len())
	}

	for name, want := range map[string]bool{
		"ads.example.com.":     true,
		"x.y.ads.example.com.": true,  // subdomains are blocked
		"ADS.EXAMPLE.COM":      true,  // case-insensitive
		"tracker.net.":         true,  // hosts-file format
		"example.com.":         false, // the parent is not blocked
		"badads.example.com.":  false, // must match whole labels
		".":                    false,
	} {
		if got := l.Blocked(name); got != want {
			t.Errorf("Blocked(%q) = %v, want %v", name, got, want)
		}
	}

	var empty *List
	if empty.Blocked("ads.example.com.") {
		t.Error("nil list should block nothing")
	}
}
