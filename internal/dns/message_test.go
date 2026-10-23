package dns

import (
	"bytes"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func TestPackParseRoundTrip(t *testing.T) {
	ip := netip.MustParseAddr("192.168.1.10")
	in := &Message{
		Header:    Header{ID: 0xBEEF, Response: true, Authoritative: true, RecursionDesired: true, RCode: RCodeNXDomain},
		Questions: []Question{{Name: "www.Example.com.", Type: TypeA, Class: ClassIN}},
		Answers:   []Record{{Name: "www.example.com.", Type: TypeA, Class: ClassIN, TTL: 300, Data: AData(ip)}},
	}
	b, err := in.Pack()
	if err != nil {
		t.Fatal(err)
	}
	out, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}

	if out.Header != in.Header {
		t.Errorf("header = %+v, want %+v", out.Header, in.Header)
	}
	if out.Questions[0] != in.Questions[0] {
		t.Errorf("question = %+v, want %+v", out.Questions[0], in.Questions[0])
	}
	a := out.Answers[0]
	if a.Name != "www.example.com." || a.TTL != 300 || !bytes.Equal(a.Data, ip.AsSlice()) {
		t.Errorf("answer = %+v", a)
	}
	// TTLOffset must point at the TTL bytes inside b.
	if got := b[a.TTLOffset : a.TTLOffset+4]; !bytes.Equal(got, []byte{0, 0, 1, 44}) {
		t.Errorf("bytes at TTLOffset = %v, want TTL 300", got)
	}
}

func TestParseCompressedName(t *testing.T) {
	// Header with 1 question and 1 answer, then:
	//   question: example.com. A IN               (offset 12)
	//   answer:   pointer to offset 12 ("example.com."), A IN, TTL 60, 4 bytes
	msg := []byte{
		0, 1, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0,
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1,
		0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4,
	}
	m, err := Parse(msg)
	if err != nil {
		t.Fatal(err)
	}
	if got := m.Answers[0].Name; got != "example.com." {
		t.Errorf("compressed name = %q, want example.com.", got)
	}
}

func TestParseRejectsBadMessages(t *testing.T) {
	header := []byte{0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0} // 1 question

	tests := []struct {
		name string
		msg  []byte
		want error
	}{
		{"too short", []byte{1, 2, 3}, ErrShort},
		{"missing question", header, ErrShort},
		{"pointer loop", append(header, 0xC0, 12, 0, 1, 0, 1), ErrPointer},    // points at itself
		{"forward pointer", append(header, 0xC0, 20, 0, 1, 0, 1), ErrPointer}, // points ahead
		{"reserved label", append(header, 0x40, 0, 0, 1, 0, 1), ErrLabel},     // 0b01 prefix
		{"label past end", append(header, 10, 'a', 'b'), ErrShort},            // claims 10 bytes
		{"name too long", append(header, longName()...), ErrName},             // > 255 bytes
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Parse(tc.msg); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

// longName returns a wire-format name of five 63-byte labels (320 bytes).
func longName() []byte {
	var b []byte
	for range 5 {
		b = append(b, 63)
		b = append(b, strings.Repeat("a", 63)...)
	}
	return append(b, 0, 0, 1, 0, 1)
}

func TestPackRejectsBadNames(t *testing.T) {
	for _, name := range []string{"a..b.", strings.Repeat("x", 64) + ".com.", strings.Repeat("abc.", 70)} {
		m := &Message{Questions: []Question{{Name: name, Type: TypeA, Class: ClassIN}}}
		if _, err := m.Pack(); err == nil {
			t.Errorf("Pack(%q) succeeded, want error", name)
		}
	}
}

func TestTXTDataSplitsLongText(t *testing.T) {
	data := TXTData(strings.Repeat("x", 300))
	// 1 length byte + 255 bytes, then 1 length byte + 45 bytes.
	if len(data) != 302 || data[0] != 255 || data[256] != 45 {
		t.Fatalf("unexpected TXT encoding: len=%d first=%d second=%d", len(data), data[0], data[256])
	}
}

func TestTCPFraming(t *testing.T) {
	msg := make([]byte, 20)
	msg[0] = 7
	var buf bytes.Buffer
	if err := WriteTCP(&buf, msg); err != nil {
		t.Fatal(err)
	}
	if got := buf.Bytes()[:2]; !bytes.Equal(got, []byte{0, 20}) {
		t.Fatalf("length prefix = %v, want [0 20]", got)
	}
	got, err := ReadTCP(&buf)
	if err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("ReadTCP = %v, %v", got, err)
	}
}
