package dns

import (
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
)

// This file builds RDATA (the record-specific payload) for common record
// types, and frames messages for DNS over TCP.

// AData returns the RDATA of an A record: the 4 address bytes.
func AData(ip netip.Addr) []byte {
	b := ip.As4()
	return b[:]
}

// AAAAData returns the RDATA of an AAAA record: the 16 address bytes.
func AAAAData(ip netip.Addr) []byte {
	b := ip.As16()
	return b[:]
}

// NameData returns the RDATA of a record that holds one name (CNAME, NS, PTR).
func NameData(name string) ([]byte, error) {
	return appendName(nil, name)
}

// MXData returns the RDATA of an MX record: a 16-bit preference
// (lower = preferred) followed by the mail server's name.
func MXData(pref uint16, host string) ([]byte, error) {
	return appendName(binary.BigEndian.AppendUint16(nil, pref), host)
}

// TXTData returns the RDATA of a TXT record. TXT data is a sequence of
// length-prefixed strings of at most 255 bytes each, so longer text is split.
func TXTData(text string) []byte {
	var b []byte
	for {
		chunk := text[:min(len(text), 255)]
		b = append(b, byte(len(chunk)))
		b = append(b, chunk...)
		text = text[len(chunk):]
		if text == "" {
			return b
		}
	}
}

// ReadTCP reads one DNS message from a TCP stream. Over TCP every message is
// preceded by its length as a 2-byte big-endian integer (RFC 1035 4.2.2).
func ReadTCP(r io.Reader) ([]byte, error) {
	var n [2]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint16(n[:])
	if size < HeaderLen {
		return nil, errors.New("dns: TCP message shorter than a header")
	}
	msg := make([]byte, size)
	if _, err := io.ReadFull(r, msg); err != nil {
		return nil, err
	}
	return msg, nil
}

// WriteTCP writes one length-prefixed DNS message to a TCP stream.
func WriteTCP(w io.Writer, msg []byte) error {
	if len(msg) > 0xFFFF {
		return errors.New("dns: message too large for TCP")
	}
	_, err := w.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(msg))), msg...))
	return err
}
