// Package dns encodes and decodes DNS messages in the binary wire format
// described in RFC 1035, section 4.
//
// Every DNS message, query or response, has the same layout:
//
//	+---------------------+
//	|       Header        |  12 bytes: ID, flags, four section counts
//	+---------------------+
//	|      Question       |  what is being asked (name, type, class)
//	+---------------------+
//	|       Answer        |  resource records answering the question
//	+---------------------+
//	|      Authority      |  records pointing to authoritative servers
//	+---------------------+
//	|     Additional      |  extra records (e.g. the EDNS OPT record)
//	+---------------------+
//
// Names are written as length-prefixed labels: "www.example.com." becomes
// 3 'w' 'w' 'w' 7 'e' 'x' 'a' 'm' 'p' 'l' 'e' 3 'c' 'o' 'm' 0.
// To save space a name may end in a 2-byte pointer to an earlier copy of the
// rest of the name ("message compression").
package dns

import (
	"encoding/binary"
	"errors"
	"strconv"
	"strings"
)

// Record types this project understands. The full list is maintained by IANA.
const (
	TypeA     uint16 = 1   // IPv4 address
	TypeNS    uint16 = 2   // name server
	TypeCNAME uint16 = 5   // alias to another name
	TypeSOA   uint16 = 6   // start of authority (zone metadata)
	TypePTR   uint16 = 12  // reverse lookup
	TypeMX    uint16 = 15  // mail exchanger
	TypeTXT   uint16 = 16  // free text
	TypeAAAA  uint16 = 28  // IPv6 address
	TypeOPT   uint16 = 41  // EDNS(0) pseudo-record
	TypeANY   uint16 = 255 // "all records" (query only)
)

// ClassIN is the Internet class. It is practically the only one in use.
const ClassIN uint16 = 1

// Response codes (RCODE).
const (
	RCodeSuccess  uint8 = 0 // NOERROR
	RCodeFormErr  uint8 = 1 // the query was malformed
	RCodeServFail uint8 = 2 // the server failed (e.g. upstream unreachable)
	RCodeNXDomain uint8 = 3 // the name does not exist
	RCodeNotImp   uint8 = 4 // query kind not supported
	RCodeRefused  uint8 = 5 // the server refuses to answer
)

const (
	// HeaderLen is the fixed size of the DNS header.
	HeaderLen = 12
	// MaxUDPSize is the classic UDP response limit. Clients may advertise a
	// bigger one with EDNS(0).
	MaxUDPSize = 512

	maxNameLen  = 255
	maxLabelLen = 63
)

var (
	ErrShort   = errors.New("dns: message too short")
	ErrPointer = errors.New("dns: invalid compression pointer")
	ErrLabel   = errors.New("dns: invalid label")
	ErrName    = errors.New("dns: name longer than 255 bytes")
	ErrData    = errors.New("dns: record data longer than 65535 bytes")
)

var typeNames = map[uint16]string{
	TypeA: "A", TypeNS: "NS", TypeCNAME: "CNAME", TypeSOA: "SOA", TypePTR: "PTR",
	TypeMX: "MX", TypeTXT: "TXT", TypeAAAA: "AAAA", TypeOPT: "OPT", TypeANY: "ANY",
}

var rcodeNames = map[uint8]string{
	RCodeSuccess: "NOERROR", RCodeFormErr: "FORMERR", RCodeServFail: "SERVFAIL",
	RCodeNXDomain: "NXDOMAIN", RCodeNotImp: "NOTIMP", RCodeRefused: "REFUSED",
}

// TypeString returns the mnemonic for a record type, e.g. "AAAA" or "TYPE99".
func TypeString(t uint16) string {
	if s, ok := typeNames[t]; ok {
		return s
	}
	return "TYPE" + strconv.Itoa(int(t))
}

// RCodeString returns the mnemonic for a response code, e.g. "NXDOMAIN".
func RCodeString(rc uint8) string {
	if s, ok := rcodeNames[rc]; ok {
		return s
	}
	return "RCODE" + strconv.Itoa(int(rc))
}

// Header is the 12-byte message header with the flags unpacked.
//
// The 16 flag bits are laid out as:
//
//	 15  14-11   10  9   8   7   6-4   3-0
//	|QR| Opcode |AA|TC|RD|RA|  Z  | RCODE |
type Header struct {
	ID                 uint16 // copied from query to response so clients can match them
	Response           bool   // QR: false = query, true = response
	Opcode             uint8  // 0 = standard query
	Authoritative      bool   // AA: the answer comes from the zone's own server
	Truncated          bool   // TC: the response was cut short; retry over TCP
	RecursionDesired   bool   // RD: client asks the server to resolve fully
	RecursionAvailable bool   // RA: server supports recursion
	RCode              uint8  // response code
}

func (h Header) flags() uint16 {
	var f uint16
	if h.Response {
		f |= 1 << 15
	}
	f |= uint16(h.Opcode&0xF) << 11
	if h.Authoritative {
		f |= 1 << 10
	}
	if h.Truncated {
		f |= 1 << 9
	}
	if h.RecursionDesired {
		f |= 1 << 8
	}
	if h.RecursionAvailable {
		f |= 1 << 7
	}
	return f | uint16(h.RCode&0xF)
}

func parseHeader(b []byte) Header {
	f := binary.BigEndian.Uint16(b[2:])
	return Header{
		ID:                 binary.BigEndian.Uint16(b),
		Response:           f&(1<<15) != 0,
		Opcode:             uint8(f>>11) & 0xF,
		Authoritative:      f&(1<<10) != 0,
		Truncated:          f&(1<<9) != 0,
		RecursionDesired:   f&(1<<8) != 0,
		RecursionAvailable: f&(1<<7) != 0,
		RCode:              uint8(f & 0xF),
	}
}

// Question is one entry of the question section.
type Question struct {
	Name  string // fully qualified, with trailing dot, case as received
	Type  uint16
	Class uint16
}

// Record is a resource record. Data holds the raw RDATA bytes; helpers in
// rdata.go build it for common types.
type Record struct {
	Name  string
	Type  uint16
	Class uint16
	TTL   uint32 // seconds the record may be cached
	Data  []byte

	// TTLOffset is where the TTL field sits in the message this record was
	// parsed from (0 for records built in code). The cache uses it to lower
	// TTLs in place without re-encoding the message.
	TTLOffset int
}

// Message is a complete DNS message.
type Message struct {
	Header
	Questions  []Question
	Answers    []Record
	Authority  []Record
	Additional []Record
}

// NewReply returns a response skeleton for query q: same ID, opcode, RD flag
// and question, with RA set and the given response code.
func NewReply(q *Message, rcode uint8) *Message {
	return &Message{
		Header: Header{
			ID:                 q.ID,
			Response:           true,
			Opcode:             q.Opcode,
			RecursionDesired:   q.RecursionDesired,
			RecursionAvailable: true,
			RCode:              rcode,
		},
		Questions: q.Questions,
	}
}

// Parse decodes a DNS message. Record Data slices point into b, so b must not
// be modified while the result is in use.
func Parse(b []byte) (*Message, error) {
	if len(b) < HeaderLen {
		return nil, ErrShort
	}
	m := &Message{Header: parseHeader(b)}
	qd := int(binary.BigEndian.Uint16(b[4:]))
	an := int(binary.BigEndian.Uint16(b[6:]))
	ns := int(binary.BigEndian.Uint16(b[8:]))
	ar := int(binary.BigEndian.Uint16(b[10:]))

	off := HeaderLen
	for range qd {
		name, next, err := readName(b, off)
		if err != nil {
			return nil, err
		}
		if next+4 > len(b) {
			return nil, ErrShort
		}
		m.Questions = append(m.Questions, Question{
			Name:  name,
			Type:  binary.BigEndian.Uint16(b[next:]),
			Class: binary.BigEndian.Uint16(b[next+2:]),
		})
		off = next + 4
	}

	var err error
	for _, sec := range []struct {
		count int
		dst   *[]Record
	}{{an, &m.Answers}, {ns, &m.Authority}, {ar, &m.Additional}} {
		for range sec.count {
			var rr Record
			if rr, off, err = readRecord(b, off); err != nil {
				return nil, err
			}
			*sec.dst = append(*sec.dst, rr)
		}
	}
	return m, nil
}

func readRecord(b []byte, off int) (Record, int, error) {
	name, off, err := readName(b, off)
	if err != nil {
		return Record{}, 0, err
	}
	if off+10 > len(b) {
		return Record{}, 0, ErrShort
	}
	rr := Record{
		Name:      name,
		Type:      binary.BigEndian.Uint16(b[off:]),
		Class:     binary.BigEndian.Uint16(b[off+2:]),
		TTL:       binary.BigEndian.Uint32(b[off+4:]),
		TTLOffset: off + 4,
	}
	n := int(binary.BigEndian.Uint16(b[off+8:]))
	off += 10
	if off+n > len(b) {
		return Record{}, 0, ErrShort
	}
	rr.Data = b[off : off+n]
	return rr, off + n, nil
}

// readName decodes the name starting at off, following compression
// pointers. It returns the name and the offset just past it in the
// original position (a pointer counts as 2 bytes there).
func readName(b []byte, off int) (string, int, error) {
	var sb strings.Builder
	end := -1 // offset after the name, fixed at the first pointer
	length := 0

	for {
		if off >= len(b) {
			return "", 0, ErrShort
		}
		l := int(b[off])
		switch l & 0xC0 {
		case 0x00: // a normal label of length l (0 = end of name)
			off++
			if l == 0 {
				if end < 0 {
					end = off
				}
				if sb.Len() == 0 {
					return ".", end, nil
				}
				return sb.String(), end, nil
			}
			if off+l > len(b) {
				return "", 0, ErrShort
			}
			if length += l + 1; length > maxNameLen {
				return "", 0, ErrName
			}
			sb.Write(b[off : off+l])
			sb.WriteByte('.')
			off += l

		case 0xC0: // a pointer: the low 14 bits are an offset into the message
			if off+1 >= len(b) {
				return "", 0, ErrShort
			}
			ptr := int(binary.BigEndian.Uint16(b[off:]) & 0x3FFF)
			if end < 0 {
				end = off + 2
			}
			// Pointers must jump strictly backwards. That alone rules out
			// loops, a classic way to hang naive DNS parsers.
			if ptr >= off {
				return "", 0, ErrPointer
			}
			off = ptr

		default: // 0x40 and 0x80 prefixes are reserved
			return "", 0, ErrLabel
		}
	}
}

// Pack encodes the message. Names are written without compression, which
// is always valid, just a little larger.
func (m *Message) Pack() ([]byte, error) {
	b := make([]byte, HeaderLen, MaxUDPSize)
	binary.BigEndian.PutUint16(b[0:], m.ID)
	binary.BigEndian.PutUint16(b[2:], m.flags())
	binary.BigEndian.PutUint16(b[4:], uint16(len(m.Questions)))
	binary.BigEndian.PutUint16(b[6:], uint16(len(m.Answers)))
	binary.BigEndian.PutUint16(b[8:], uint16(len(m.Authority)))
	binary.BigEndian.PutUint16(b[10:], uint16(len(m.Additional)))

	var err error
	for _, q := range m.Questions {
		if b, err = appendName(b, q.Name); err != nil {
			return nil, err
		}
		b = binary.BigEndian.AppendUint16(b, q.Type)
		b = binary.BigEndian.AppendUint16(b, q.Class)
	}
	for _, sec := range [][]Record{m.Answers, m.Authority, m.Additional} {
		for _, rr := range sec {
			if len(rr.Data) > 0xFFFF {
				return nil, ErrData
			}
			if b, err = appendName(b, rr.Name); err != nil {
				return nil, err
			}
			b = binary.BigEndian.AppendUint16(b, rr.Type)
			b = binary.BigEndian.AppendUint16(b, rr.Class)
			b = binary.BigEndian.AppendUint32(b, rr.TTL)
			b = binary.BigEndian.AppendUint16(b, uint16(len(rr.Data)))
			b = append(b, rr.Data...)
		}
	}
	return b, nil
}

// appendName appends name in wire format. A missing trailing dot is allowed.
func appendName(b []byte, name string) ([]byte, error) {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return append(b, 0), nil // the root name
	}
	if len(name)+2 > maxNameLen {
		return nil, ErrName
	}
	for label := range strings.SplitSeq(name, ".") {
		if len(label) == 0 || len(label) > maxLabelLen {
			return nil, ErrLabel
		}
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	return append(b, 0), nil
}
