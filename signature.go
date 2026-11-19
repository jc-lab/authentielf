package authentielf

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"time"
	"unicode/utf16"

	"github.com/jc-lab/authentielf/internal/cms"
	"github.com/jc-lab/authentielf/internal/tsp"
)

// Object identifiers. All except OIDSpcElfImageDataV1 are the ones used by
// Microsoft Authenticode, so the PKCS#7 structure is the same as a PE
// signature apart from the image data type.
var (
	// OIDSpcElfImageDataV1 (SPC_ELF_IMAGE_DATA_OBJID_V1) is the
	// SpcIndirectDataContent.data.type of an AuthentiELF signature.
	OIDSpcElfImageDataV1 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 62615, 1001, 1, 21}

	OIDSpcIndirectData       = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 4}
	OIDSpcStatementType      = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 11}
	OIDSpcSpOpusInfo         = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 12}
	OIDSpcIndividualSPKeyPur = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 21}
	OIDNestedSignature       = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 4, 1}
	OIDRFC3161Timestamp      = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 3, 3, 1}
)

const maxNestingDepth = 4

// Signature is one Authenticode-style signature: a PKCS#7 SignedData with a
// single signer over an SpcIndirectDataContent. A file carries one primary
// signature; additional signatures are nested in the primary signer's
// unsigned attributes (szOID_NESTED_SIGNATURE), exactly like signtool /as.
type Signature struct {
	sd *cms.SignedData
	si *cms.SignerInfo

	// HashAlgorithm and ImageDigest come from SpcIndirectDataContent.
	HashAlgorithm crypto.Hash
	ImageDigest   []byte

	// Signer is the signing certificate (nil if not embedded).
	Signer       *x509.Certificate
	Certificates []*x509.Certificate

	ProgramName string
	MoreInfoURL string

	// Timestamp is the parsed RFC 3161 counter-signature (not verified).
	Timestamp *Timestamp
}

// Timestamp describes an RFC 3161 timestamp token attached to a signature.
type Timestamp struct {
	Time          time.Time
	HashAlgorithm crypto.Hash
	Signer        *x509.Certificate // TSA certificate (nil if not embedded)
	Raw           []byte            // TimeStampToken DER
	token         *tsp.Token
}

type spcAttributeTypeAndOptionalValue struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"optional"`
}

type digestInfo struct {
	DigestAlgorithm pkix.AlgorithmIdentifier
	Digest          []byte
}

type spcIndirectDataContent struct {
	Data          spcAttributeTypeAndOptionalValue
	MessageDigest digestInfo
}

func encodeIndirectData(h crypto.Hash, digest []byte) ([]byte, error) {
	oid, err := cms.OIDForHash(h)
	if err != nil {
		return nil, err
	}
	return cms.Seq(
		cms.Seq(cms.OID(OIDSpcElfImageDataV1)),
		cms.Seq(cms.AlgorithmIdentifier(oid, true), cms.OctetString(digest)),
	), nil
}

// encodeOpusInfo builds SpcSpOpusInfo { programName [0] SpcString (unicode),
// moreInfo [1] SpcLink (url) }.
func encodeOpusInfo(name, url string) []byte {
	var parts [][]byte
	if name != "" {
		u := utf16.Encode([]rune(name))
		b := make([]byte, 2*len(u))
		for i, c := range u {
			b[2*i], b[2*i+1] = byte(c>>8), byte(c)
		}
		parts = append(parts, cms.Ctx(0, cms.TLV(0x80, b)))
	}
	if url != "" {
		parts = append(parts, cms.Ctx(1, cms.TLV(0x80, []byte(url))))
	}
	return cms.Seq(parts...)
}

func parseOpusInfo(der []byte) (name, url string) {
	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(der, &seq); err != nil {
		return
	}
	elems, _ := cms.SplitElements(seq.Bytes)
	for _, e := range elems {
		var outer, inner asn1.RawValue
		if _, err := asn1.Unmarshal(e, &outer); err != nil || outer.Class != asn1.ClassContextSpecific {
			continue
		}
		if _, err := asn1.Unmarshal(outer.Bytes, &inner); err != nil || inner.Class != asn1.ClassContextSpecific {
			continue
		}
		switch {
		case outer.Tag == 0 && inner.Tag == 0 && len(inner.Bytes)%2 == 0: // unicode
			u := make([]uint16, len(inner.Bytes)/2)
			for i := range u {
				u[i] = uint16(inner.Bytes[2*i])<<8 | uint16(inner.Bytes[2*i+1])
			}
			name = string(utf16.Decode(u))
		case outer.Tag == 0 && inner.Tag == 1: // ascii
			name = string(inner.Bytes)
		case outer.Tag == 1 && inner.Tag == 0: // url
			url = string(inner.Bytes)
		}
	}
	return
}

func newSignature(sd *cms.SignedData) (*Signature, error) {
	if len(sd.Signers) != 1 {
		return nil, fmt.Errorf("authentielf: signature must have exactly one signer, has %d", len(sd.Signers))
	}
	if !sd.ContentType.Equal(OIDSpcIndirectData) {
		return nil, fmt.Errorf("authentielf: content type %v is not SpcIndirectDataContent", sd.ContentType)
	}
	var idc spcIndirectDataContent
	if rest, err := asn1.Unmarshal(sd.Content, &idc); err != nil || len(rest) != 0 {
		return nil, fmt.Errorf("authentielf: malformed SpcIndirectDataContent: %v", err)
	}
	if !idc.Data.Type.Equal(OIDSpcElfImageDataV1) {
		return nil, fmt.Errorf("authentielf: image data type %v is not SPC_ELF_IMAGE_DATA_OBJID_V1", idc.Data.Type)
	}
	h, err := cms.HashForOID(idc.MessageDigest.DigestAlgorithm.Algorithm)
	if err != nil {
		return nil, fmt.Errorf("authentielf: %w", err)
	}
	if len(idc.MessageDigest.Digest) != h.Size() {
		return nil, errors.New("authentielf: image digest has wrong length")
	}
	s := &Signature{
		sd:            sd,
		si:            sd.Signers[0],
		HashAlgorithm: h,
		ImageDigest:   idc.MessageDigest.Digest,
		Certificates:  sd.Certificates,
	}
	s.Signer = sd.FindCertificate(s.si)
	if v, ok := cms.Attr(s.si.SignedAttrs, OIDSpcSpOpusInfo); ok && len(v) == 1 {
		s.ProgramName, s.MoreInfoURL = parseOpusInfo(v[0])
	}
	if err := s.loadTimestamp(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Signature) loadTimestamp() error {
	s.Timestamp = nil
	v, ok := cms.Attr(s.si.UnsignedAttrs, OIDRFC3161Timestamp)
	if !ok {
		return nil
	}
	if len(v) != 1 || cms.AttrCount(s.si.UnsignedAttrs, OIDRFC3161Timestamp) != 1 {
		return errors.New("authentielf: multiple timestamp tokens")
	}
	tok, err := tsp.ParseToken(v[0])
	if err != nil {
		return fmt.Errorf("authentielf: timestamp: %w", err)
	}
	s.Timestamp = &Timestamp{
		Time:          tok.Info.GenTime,
		HashAlgorithm: tok.Info.HashAlgorithm,
		Signer:        tok.Signer(),
		Raw:           v[0],
		token:         tok,
	}
	return nil
}

// Encode returns the DER of this signature alone (without nested signatures).
func (s *Signature) Encode() []byte { return s.sd.Encode() }

// SignatureValue returns the signer's encrypted digest (the value an RFC 3161
// timestamp's message imprint is computed over).
func (s *Signature) SignatureValue() []byte { return s.si.Signature }

// parseSignatures decodes a PKCS#7 blob into a flat list: the primary
// signature followed by its nested signatures (depth-first). Nested
// attributes are detached from each Signature; encodeSignatures re-attaches
// them to the primary.
func parseSignatures(der []byte) ([]*Signature, error) {
	return parseSignatureTree(der, 0)
}

func parseSignatureTree(der []byte, depth int) ([]*Signature, error) {
	if depth > maxNestingDepth {
		return nil, errors.New("authentielf: nested signatures too deep")
	}
	sd, err := cms.Parse(der)
	if err != nil {
		return nil, fmt.Errorf("authentielf: %w", err)
	}
	if enc := sd.Encode(); !bytes.Equal(enc, der) {
		// Re-encoding must be lossless, otherwise editing unsigned
		// attributes could silently alter the signature.
		return nil, errors.New("authentielf: signature is not in canonical DER form")
	}
	sig, err := newSignature(sd)
	if err != nil {
		return nil, err
	}
	out := []*Signature{sig}
	for _, a := range sig.si.UnsignedAttrs {
		if !a.Type.Equal(OIDNestedSignature) {
			continue
		}
		for _, v := range a.Values {
			nested, err := parseSignatureTree(v, depth+1)
			if err != nil {
				return nil, fmt.Errorf("nested signature: %w", err)
			}
			out = append(out, nested...)
		}
	}
	sig.si.SetUnsignedAttr(OIDNestedSignature, nil)
	return out, nil
}

func encodeSignatures(sigs []*Signature) []byte {
	if len(sigs) == 0 {
		return nil
	}
	nested := make([][]byte, 0, len(sigs)-1)
	for _, s := range sigs[1:] {
		nested = append(nested, s.Encode())
	}
	primary := sigs[0].si
	saved := primary.UnsignedAttrs
	primary.SetUnsignedAttr(OIDNestedSignature, nested)
	der := sigs[0].Encode()
	primary.UnsignedAttrs = saved
	return der
}

// ReadSignatures returns all signatures in the file: index 0 is the primary
// signature, the rest are nested signatures in order.
func ReadSignatures(data []byte) ([]*Signature, error) {
	p, err := ReadPKCS7(data)
	if err != nil {
		return nil, err
	}
	return parseSignatures(p)
}

// WriteSignatures stores sigs (primary first) in a prepared file. An empty
// list removes all signatures but keeps the section.
func WriteSignatures(data []byte, sigs []*Signature) ([]byte, error) {
	return WritePKCS7(data, encodeSignatures(sigs))
}

// RemoveSignature removes the signature at index (0 = primary; the first
// nested signature is then promoted to primary).
func RemoveSignature(data []byte, index int) ([]byte, error) {
	sigs, err := ReadSignatures(data)
	if err != nil {
		return nil, err
	}
	if index < 0 || index >= len(sigs) {
		return nil, fmt.Errorf("authentielf: signature index %d out of range (have %d)", index, len(sigs))
	}
	sigs = append(sigs[:index], sigs[index+1:]...)
	return WriteSignatures(data, sigs)
}
