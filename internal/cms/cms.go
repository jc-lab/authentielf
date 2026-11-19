// Package cms implements the subset of PKCS#7 / CMS SignedData (RFC 2315,
// RFC 5652) needed for Authenticode-style signatures and RFC 3161 timestamp
// tokens.
//
// Parsed structures keep the exact DER of every signed part (content,
// signed attributes, certificates) so that unsigned attributes can be edited
// and the structure re-encoded without invalidating existing signatures.
package cms

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
)

var (
	OIDData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	OIDSignedData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	OIDContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	OIDMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}

	OIDSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	OIDSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	OIDSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	OIDSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}

	OIDRSAEncryption   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	OIDSHA1WithRSA     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	OIDSHA256WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	OIDSHA384WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	OIDSHA512WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	OIDECPublicKey     = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	OIDECDSAWithSHA1   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}
	OIDECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	OIDECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	OIDECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
)

var hashOIDs = []struct {
	h   crypto.Hash
	oid asn1.ObjectIdentifier
}{
	{crypto.SHA1, OIDSHA1},
	{crypto.SHA256, OIDSHA256},
	{crypto.SHA384, OIDSHA384},
	{crypto.SHA512, OIDSHA512},
}

// HashForOID maps a digest algorithm OID to a crypto.Hash.
func HashForOID(oid asn1.ObjectIdentifier) (crypto.Hash, error) {
	for _, e := range hashOIDs {
		if e.oid.Equal(oid) {
			return e.h, nil
		}
	}
	return 0, fmt.Errorf("cms: unsupported digest algorithm %v", oid)
}

// OIDForHash maps a crypto.Hash to its digest algorithm OID.
func OIDForHash(h crypto.Hash) (asn1.ObjectIdentifier, error) {
	for _, e := range hashOIDs {
		if e.h == h {
			return e.oid, nil
		}
	}
	return nil, fmt.Errorf("cms: unsupported hash %v", h)
}

// Attribute is a CMS attribute; Values holds the DER of each value.
type Attribute struct {
	Type   asn1.ObjectIdentifier
	Values [][]byte
}

func (a Attribute) encode(sortValues bool) []byte {
	var vals []byte
	if sortValues {
		vals = SetOf(a.Values...)
	} else {
		vals = TLV(TagSet, a.Values...)
	}
	return Seq(OID(a.Type), vals)
}

// SignerInfo is a CMS SignerInfo.
type SignerInfo struct {
	Version int

	// Signer identifier: either issuer+serial or a subject key identifier.
	rawSID       []byte
	Issuer       []byte // raw DER Name
	SerialNumber *big.Int
	SubjectKeyID []byte

	rawDigestAlgorithm []byte
	DigestAlgorithm    pkix.AlgorithmIdentifier

	// rawSignedAttrs is the [0] IMPLICIT SET exactly as signed (nil if absent).
	rawSignedAttrs []byte
	SignedAttrs    []Attribute

	rawSignatureAlgorithm []byte
	SignatureAlgorithm    pkix.AlgorithmIdentifier
	Signature             []byte

	// UnsignedAttrs may be modified freely; they are not covered by Signature.
	UnsignedAttrs []Attribute
}

// SignedData is a CMS SignedData wrapped in a ContentInfo.
type SignedData struct {
	Version          int
	digestAlgorithms [][]byte
	ContentType      asn1.ObjectIdentifier
	// Content is the DER of the encapsulated content element (the value
	// inside eContent [0] EXPLICIT); nil for detached content.
	Content         []byte
	rawCertificates [][]byte
	Certificates    []*x509.Certificate
	rawCRLs         []byte // [1] IMPLICIT, preserved verbatim
	Signers         []*SignerInfo
}

type rawContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"optional,tag:0"`
}

type rawSignedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue
	EncapContentInfo rawContentInfo
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos      asn1.RawValue
}

type rawSignerInfo struct {
	Version            int
	SID                asn1.RawValue
	DigestAlgorithm    asn1.RawValue
	SignedAttrs        asn1.RawValue `asn1:"optional,tag:0"`
	SignatureAlgorithm asn1.RawValue
	Signature          []byte
	UnsignedAttrs      asn1.RawValue `asn1:"optional,tag:1"`
}

type rawAttribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue
}

type issuerAndSerial struct {
	Issuer asn1.RawValue
	Serial *big.Int
}

func unmarshalExact(b []byte, v any) error {
	rest, err := asn1.Unmarshal(b, v)
	if err != nil {
		return err
	}
	if len(rest) != 0 {
		return errors.New("trailing data")
	}
	return nil
}

func expectTag(rv asn1.RawValue, class, tag int, compound bool) error {
	if rv.Class != class || rv.Tag != tag || rv.IsCompound != compound {
		return fmt.Errorf("unexpected ASN.1 tag class=%d tag=%d", rv.Class, rv.Tag)
	}
	return nil
}

// Parse parses a DER ContentInfo containing SignedData.
func Parse(der []byte) (*SignedData, error) {
	var ci rawContentInfo
	if err := unmarshalExact(der, &ci); err != nil {
		return nil, fmt.Errorf("cms: ContentInfo: %w", err)
	}
	if !ci.ContentType.Equal(OIDSignedData) {
		return nil, fmt.Errorf("cms: content type %v is not signedData", ci.ContentType)
	}
	if len(ci.Content.FullBytes) == 0 {
		return nil, errors.New("cms: missing signedData content")
	}
	var rsd rawSignedData
	if err := unmarshalExact(ci.Content.Bytes, &rsd); err != nil {
		return nil, fmt.Errorf("cms: SignedData: %w", err)
	}
	sd := &SignedData{Version: rsd.Version, ContentType: rsd.EncapContentInfo.ContentType}
	var err error
	if err := expectTag(rsd.DigestAlgorithms, asn1.ClassUniversal, asn1.TagSet, true); err != nil {
		return nil, fmt.Errorf("cms: digestAlgorithms: %w", err)
	}
	if sd.digestAlgorithms, err = SplitElements(rsd.DigestAlgorithms.Bytes); err != nil {
		return nil, fmt.Errorf("cms: digestAlgorithms: %w", err)
	}
	if c := rsd.EncapContentInfo.Content; len(c.FullBytes) != 0 {
		if !c.IsCompound {
			return nil, errors.New("cms: eContent must be explicitly tagged")
		}
		var inner asn1.RawValue
		if err := unmarshalExact(c.Bytes, &inner); err != nil {
			return nil, fmt.Errorf("cms: eContent: %w", err)
		}
		sd.Content = inner.FullBytes
	}
	if len(rsd.Certificates.FullBytes) != 0 {
		if !rsd.Certificates.IsCompound {
			return nil, errors.New("cms: malformed certificates")
		}
		if sd.rawCertificates, err = SplitElements(rsd.Certificates.Bytes); err != nil {
			return nil, fmt.Errorf("cms: certificates: %w", err)
		}
		for _, rc := range sd.rawCertificates {
			if rc[0] != TagSequence { // other CertificateChoices are kept but ignored
				continue
			}
			c, err := x509.ParseCertificate(rc)
			if err != nil {
				return nil, fmt.Errorf("cms: certificate: %w", err)
			}
			sd.Certificates = append(sd.Certificates, c)
		}
	}
	sd.rawCRLs = rsd.CRLs.FullBytes
	if err := expectTag(rsd.SignerInfos, asn1.ClassUniversal, asn1.TagSet, true); err != nil {
		return nil, fmt.Errorf("cms: signerInfos: %w", err)
	}
	sis, err := SplitElements(rsd.SignerInfos.Bytes)
	if err != nil {
		return nil, fmt.Errorf("cms: signerInfos: %w", err)
	}
	for _, b := range sis {
		si, err := parseSignerInfo(b)
		if err != nil {
			return nil, err
		}
		sd.Signers = append(sd.Signers, si)
	}
	return sd, nil
}

func parseAttributes(set []byte) ([]Attribute, error) {
	elems, err := SplitElements(set)
	if err != nil {
		return nil, err
	}
	attrs := make([]Attribute, 0, len(elems))
	for _, e := range elems {
		var ra rawAttribute
		if err := unmarshalExact(e, &ra); err != nil {
			return nil, err
		}
		if err := expectTag(ra.Values, asn1.ClassUniversal, asn1.TagSet, true); err != nil {
			return nil, err
		}
		vals, err := SplitElements(ra.Values.Bytes)
		if err != nil {
			return nil, err
		}
		attrs = append(attrs, Attribute{Type: ra.Type, Values: vals})
	}
	return attrs, nil
}

func parseSignerInfo(der []byte) (*SignerInfo, error) {
	var r rawSignerInfo
	if err := unmarshalExact(der, &r); err != nil {
		return nil, fmt.Errorf("cms: SignerInfo: %w", err)
	}
	si := &SignerInfo{
		Version:               r.Version,
		rawSID:                r.SID.FullBytes,
		rawDigestAlgorithm:    r.DigestAlgorithm.FullBytes,
		rawSignatureAlgorithm: r.SignatureAlgorithm.FullBytes,
		Signature:             r.Signature,
	}
	switch {
	case r.SID.Class == asn1.ClassUniversal && r.SID.Tag == asn1.TagSequence:
		var ias issuerAndSerial
		if err := unmarshalExact(r.SID.FullBytes, &ias); err != nil {
			return nil, fmt.Errorf("cms: issuerAndSerialNumber: %w", err)
		}
		si.Issuer, si.SerialNumber = ias.Issuer.FullBytes, ias.Serial
	case r.SID.Class == asn1.ClassContextSpecific && r.SID.Tag == 0 && !r.SID.IsCompound:
		si.SubjectKeyID = r.SID.Bytes
	default:
		return nil, errors.New("cms: unsupported signer identifier")
	}
	if err := unmarshalExact(r.DigestAlgorithm.FullBytes, &si.DigestAlgorithm); err != nil {
		return nil, fmt.Errorf("cms: digestAlgorithm: %w", err)
	}
	if err := unmarshalExact(r.SignatureAlgorithm.FullBytes, &si.SignatureAlgorithm); err != nil {
		return nil, fmt.Errorf("cms: signatureAlgorithm: %w", err)
	}
	var err error
	if len(r.SignedAttrs.FullBytes) != 0 {
		si.rawSignedAttrs = r.SignedAttrs.FullBytes
		if si.SignedAttrs, err = parseAttributes(r.SignedAttrs.Bytes); err != nil {
			return nil, fmt.Errorf("cms: signedAttrs: %w", err)
		}
	}
	if len(r.UnsignedAttrs.FullBytes) != 0 {
		if si.UnsignedAttrs, err = parseAttributes(r.UnsignedAttrs.Bytes); err != nil {
			return nil, fmt.Errorf("cms: unsignedAttrs: %w", err)
		}
	}
	return si, nil
}

// Encode returns the DER ContentInfo for sd.
func (sd *SignedData) Encode() []byte {
	parts := [][]byte{
		MustMarshal(sd.Version),
		TLV(TagSet, sd.digestAlgorithms...),
	}
	if sd.Content != nil {
		parts = append(parts, Seq(OID(sd.ContentType), Ctx(0, sd.Content)))
	} else {
		parts = append(parts, Seq(OID(sd.ContentType)))
	}
	if len(sd.rawCertificates) > 0 {
		parts = append(parts, Ctx(0, sd.rawCertificates...))
	}
	if sd.rawCRLs != nil {
		parts = append(parts, sd.rawCRLs)
	}
	sis := make([][]byte, len(sd.Signers))
	for i, si := range sd.Signers {
		sis[i] = si.encode()
	}
	parts = append(parts, TLV(TagSet, sis...))
	return Seq(OID(OIDSignedData), Ctx(0, Seq(parts...)))
}

func (si *SignerInfo) encode() []byte {
	parts := [][]byte{MustMarshal(si.Version), si.rawSID, si.rawDigestAlgorithm}
	if si.rawSignedAttrs != nil {
		parts = append(parts, si.rawSignedAttrs)
	}
	parts = append(parts, si.rawSignatureAlgorithm, OctetString(si.Signature))
	if len(si.UnsignedAttrs) > 0 {
		attrs := make([][]byte, len(si.UnsignedAttrs))
		for i, a := range si.UnsignedAttrs {
			// Keep value order: for nested signatures it defines numbering.
			attrs[i] = a.encode(false)
		}
		parts = append(parts, Ctx(1, attrs...))
	}
	return Seq(parts...)
}

// ContentBytes returns the bytes the messageDigest attribute is computed
// over: the contents octets of the encapsulated content element (for an
// OCTET STRING its value, for Authenticode's SpcIndirectDataContent the
// SEQUENCE body without tag and length).
func (sd *SignedData) ContentBytes() ([]byte, error) {
	if sd.Content == nil {
		return nil, errors.New("cms: no encapsulated content")
	}
	var rv asn1.RawValue
	if err := unmarshalExact(sd.Content, &rv); err != nil {
		return nil, err
	}
	if rv.Class == asn1.ClassUniversal && rv.Tag == asn1.TagOctetString && rv.IsCompound {
		return nil, errors.New("cms: constructed OCTET STRING content not supported")
	}
	return rv.Bytes, nil
}

// Attr returns the values of the first attribute of the given type.
func Attr(attrs []Attribute, oid asn1.ObjectIdentifier) ([][]byte, bool) {
	for _, a := range attrs {
		if a.Type.Equal(oid) {
			return a.Values, true
		}
	}
	return nil, false
}

// AttrCount returns how many attributes of the given type are present.
func AttrCount(attrs []Attribute, oid asn1.ObjectIdentifier) int {
	n := 0
	for _, a := range attrs {
		if a.Type.Equal(oid) {
			n++
		}
	}
	return n
}

// SetUnsignedAttr replaces all unsigned attributes of the given type with a
// single attribute holding values (or removes them if values is empty).
func (si *SignerInfo) SetUnsignedAttr(oid asn1.ObjectIdentifier, values [][]byte) {
	out := si.UnsignedAttrs[:0:0]
	for _, a := range si.UnsignedAttrs {
		if !a.Type.Equal(oid) {
			out = append(out, a)
		}
	}
	if len(values) > 0 {
		out = append(out, Attribute{Type: oid, Values: values})
	}
	si.UnsignedAttrs = out
}

// FindCertificate returns the certificate identified by si's SID.
func (sd *SignedData) FindCertificate(si *SignerInfo) *x509.Certificate {
	for _, c := range sd.Certificates {
		if si.SerialNumber != nil {
			if c.SerialNumber.Cmp(si.SerialNumber) == 0 && bytes.Equal(c.RawIssuer, si.Issuer) {
				return c
			}
		} else if len(si.SubjectKeyID) > 0 && bytes.Equal(c.SubjectKeyId, si.SubjectKeyID) {
			return c
		}
	}
	return nil
}

// Verify checks si's signed attributes (content-type and message-digest
// against sd's content) and its signature. It does not verify the
// certificate chain. It returns the signer certificate.
func (sd *SignedData) Verify(si *SignerInfo) (*x509.Certificate, error) {
	cert := sd.FindCertificate(si)
	if cert == nil {
		return nil, errors.New("cms: signer certificate not found")
	}
	h, err := HashForOID(si.DigestAlgorithm.Algorithm)
	if err != nil {
		return nil, err
	}
	if si.rawSignedAttrs == nil {
		return nil, errors.New("cms: signer has no signed attributes")
	}
	if AttrCount(si.SignedAttrs, OIDContentType) != 1 || AttrCount(si.SignedAttrs, OIDMessageDigest) != 1 {
		return nil, errors.New("cms: content-type and message-digest attributes must appear exactly once")
	}
	ctv, _ := Attr(si.SignedAttrs, OIDContentType)
	var ct asn1.ObjectIdentifier
	if len(ctv) != 1 || unmarshalExact(ctv[0], &ct) != nil || !ct.Equal(sd.ContentType) {
		return nil, errors.New("cms: content-type attribute mismatch")
	}
	mdv, _ := Attr(si.SignedAttrs, OIDMessageDigest)
	var md []byte
	if len(mdv) != 1 || unmarshalExact(mdv[0], &md) != nil {
		return nil, errors.New("cms: malformed message-digest attribute")
	}
	content, err := sd.ContentBytes()
	if err != nil {
		return nil, err
	}
	hh := h.New()
	hh.Write(content)
	if !bytes.Equal(hh.Sum(nil), md) {
		return nil, errors.New("cms: message digest mismatch")
	}

	// The signature covers the DER of the attributes with a SET tag.
	signed := append([]byte{TagSet}, si.rawSignedAttrs[1:]...)
	hh = h.New()
	hh.Write(signed)
	if err := verifySignature(cert.PublicKey, si.SignatureAlgorithm.Algorithm, h, hh.Sum(nil), si.Signature); err != nil {
		return nil, err
	}
	return cert, nil
}

func verifySignature(pub any, alg asn1.ObjectIdentifier, h crypto.Hash, digest, sig []byte) error {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		switch {
		case alg.Equal(OIDRSAEncryption), alg.Equal(OIDSHA1WithRSA), alg.Equal(OIDSHA256WithRSA),
			alg.Equal(OIDSHA384WithRSA), alg.Equal(OIDSHA512WithRSA):
		default:
			return fmt.Errorf("cms: signature algorithm %v does not match RSA key", alg)
		}
		if err := rsa.VerifyPKCS1v15(k, h, digest, sig); err != nil {
			return errors.New("cms: invalid signature")
		}
	case *ecdsa.PublicKey:
		switch {
		case alg.Equal(OIDECPublicKey), alg.Equal(OIDECDSAWithSHA1), alg.Equal(OIDECDSAWithSHA256),
			alg.Equal(OIDECDSAWithSHA384), alg.Equal(OIDECDSAWithSHA512):
		default:
			return fmt.Errorf("cms: signature algorithm %v does not match ECDSA key", alg)
		}
		if !ecdsa.VerifyASN1(k, digest, sig) {
			return errors.New("cms: invalid signature")
		}
	default:
		return fmt.Errorf("cms: unsupported public key type %T", pub)
	}
	return nil
}

// New creates an unsigned SignedData. content is the DER of the
// encapsulated content element.
func New(contentType asn1.ObjectIdentifier, content []byte) *SignedData {
	return &SignedData{Version: 1, ContentType: contentType, Content: content}
}

// AddCertificates appends certificates (skipping duplicates).
func (sd *SignedData) AddCertificates(certs ...*x509.Certificate) {
next:
	for _, c := range certs {
		for _, e := range sd.Certificates {
			if bytes.Equal(e.Raw, c.Raw) {
				continue next
			}
		}
		sd.Certificates = append(sd.Certificates, c)
		sd.rawCertificates = append(sd.rawCertificates, c.Raw)
	}
}

// AddSigner signs sd's content with key and appends a SignerInfo using
// issuerAndSerialNumber. The content-type and message-digest attributes are
// added automatically; extra holds additional signed attributes.
func (sd *SignedData) AddSigner(key crypto.Signer, cert *x509.Certificate, h crypto.Hash, extra []Attribute) (*SignerInfo, error) {
	hashOID, err := OIDForHash(h)
	if err != nil {
		return nil, err
	}
	var sigAlg []byte
	switch key.Public().(type) {
	case *rsa.PublicKey:
		sigAlg = AlgorithmIdentifier(OIDRSAEncryption, true)
	case *ecdsa.PublicKey:
		m := map[crypto.Hash]asn1.ObjectIdentifier{
			crypto.SHA1: OIDECDSAWithSHA1, crypto.SHA256: OIDECDSAWithSHA256,
			crypto.SHA384: OIDECDSAWithSHA384, crypto.SHA512: OIDECDSAWithSHA512,
		}
		sigAlg = AlgorithmIdentifier(m[h], false)
	default:
		return nil, fmt.Errorf("cms: unsupported key type %T", key.Public())
	}
	content, err := sd.ContentBytes()
	if err != nil {
		return nil, err
	}
	hh := h.New()
	hh.Write(content)
	attrs := append([]Attribute{
		{Type: OIDContentType, Values: [][]byte{OID(sd.ContentType)}},
		{Type: OIDMessageDigest, Values: [][]byte{OctetString(hh.Sum(nil))}},
	}, extra...)
	encAttrs := make([][]byte, len(attrs))
	for i, a := range attrs {
		encAttrs[i] = a.encode(true)
	}
	signedSet := SetOf(encAttrs...)
	hh = h.New()
	hh.Write(signedSet)
	sig, err := key.Sign(rand.Reader, hh.Sum(nil), h)
	if err != nil {
		return nil, fmt.Errorf("cms: signing: %w", err)
	}

	raw := Seq(MustMarshal(1), Seq(cert.RawIssuer, MustMarshal(cert.SerialNumber)),
		AlgorithmIdentifier(hashOID, true), Ctx(0, mustContents(signedSet)),
		sigAlg, OctetString(sig))
	si, err := parseSignerInfo(raw)
	if err != nil {
		return nil, err
	}
	sd.Signers = append(sd.Signers, si)
	digestAlg := AlgorithmIdentifier(hashOID, true)
	found := false
	for _, d := range sd.digestAlgorithms {
		if bytes.Equal(d, digestAlg) {
			found = true
		}
	}
	if !found {
		sd.digestAlgorithms = append(sd.digestAlgorithms, digestAlg)
	}
	sd.AddCertificates(cert)
	return si, nil
}

// mustContents returns the contents octets of a DER element built by us.
func mustContents(der []byte) []byte {
	var rv asn1.RawValue
	if err := unmarshalExact(der, &rv); err != nil {
		panic(err)
	}
	return rv.Bytes
}
