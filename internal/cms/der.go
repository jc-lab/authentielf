package cms

import (
	"bytes"
	"encoding/asn1"
	"sort"
)

// Minimal DER construction helpers. encoding/asn1.Marshal ignores the
// "explicit" tag on RawValue fields and does not sort SET OF, so structures
// are assembled by hand from pre-encoded parts.

const (
	TagInteger     = 0x02
	TagOctetString = 0x04
	TagNull        = 0x05
	TagSequence    = 0x30
	TagSet         = 0x31
)

// TLV encodes a single-byte tag with the concatenation of parts as content.
func TLV(tag byte, parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n+6)
	out = append(out, tag)
	out = appendLength(out, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func appendLength(b []byte, n int) []byte {
	if n < 0x80 {
		return append(b, byte(n))
	}
	var tmp [8]byte
	i := len(tmp)
	for v := n; v > 0; v >>= 8 {
		i--
		tmp[i] = byte(v)
	}
	b = append(b, 0x80|byte(len(tmp)-i))
	return append(b, tmp[i:]...)
}

// Seq encodes a SEQUENCE.
func Seq(parts ...[]byte) []byte { return TLV(TagSequence, parts...) }

// SetOf encodes a DER SET OF (elements sorted by their encoding).
func SetOf(elems ...[]byte) []byte {
	s := append([][]byte(nil), elems...)
	sort.Slice(s, func(i, j int) bool { return bytes.Compare(s[i], s[j]) < 0 })
	return TLV(TagSet, s...)
}

// Ctx encodes a context-specific constructed [n] element with the given
// content. It serves both as an EXPLICIT wrapper (content = one element)
// and as an IMPLICIT SET/SEQUENCE (content = the elements).
func Ctx(n int, parts ...[]byte) []byte { return TLV(0xa0|byte(n), parts...) }

// OctetString encodes an OCTET STRING.
func OctetString(b []byte) []byte { return TLV(TagOctetString, b) }

// MustMarshal marshals a primitive value with encoding/asn1.
func MustMarshal(v any) []byte {
	b, err := asn1.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// OID encodes an OBJECT IDENTIFIER.
func OID(o asn1.ObjectIdentifier) []byte { return MustMarshal(o) }

// AlgorithmIdentifier encodes { algorithm, NULL } or { algorithm } when
// withNull is false.
func AlgorithmIdentifier(o asn1.ObjectIdentifier, withNull bool) []byte {
	if withNull {
		return Seq(OID(o), []byte{TagNull, 0})
	}
	return Seq(OID(o))
}

// SplitElements splits concatenated DER elements (e.g. the content of a SET).
func SplitElements(b []byte) ([][]byte, error) {
	var out [][]byte
	for len(b) > 0 {
		var rv asn1.RawValue
		rest, err := asn1.Unmarshal(b, &rv)
		if err != nil {
			return nil, err
		}
		out = append(out, rv.FullBytes)
		b = rest
	}
	return out, nil
}
