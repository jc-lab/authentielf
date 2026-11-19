package authentielf

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/jc-lab/authentielf/internal/cms"
	"github.com/jc-lab/authentielf/internal/tsp"
)

// Timestamper obtains an RFC 3161 TimeStampToken (DER ContentInfo) over a
// digest computed with h.
type Timestamper interface {
	Timestamp(ctx context.Context, h crypto.Hash, digest []byte) ([]byte, error)
}

// NewRFC3161Timestamper returns a Timestamper for an RFC 3161 HTTP(S) TSA.
func NewRFC3161Timestamper(url string) Timestamper {
	return &tsp.Client{URL: url}
}

// SignOptions configures Sign.
type SignOptions struct {
	Signer      crypto.Signer
	Certificate *x509.Certificate
	// Intermediates are embedded so verifiers can build the chain.
	Intermediates []*x509.Certificate

	// Hash is the digest algorithm (default SHA-256).
	Hash crypto.Hash

	// Append adds the new signature as a nested signature, keeping existing
	// ones. Otherwise existing signatures are replaced.
	Append bool

	// ProgramName and MoreInfoURL go into SpcSpOpusInfo (optional).
	ProgramName string
	MoreInfoURL string

	// Timestamper, if set, timestamps the new signature.
	Timestamper Timestamper
}

// Sign signs an ELF file (signed or not) and returns the new file contents.
func Sign(ctx context.Context, data []byte, opts *SignOptions) ([]byte, error) {
	if opts == nil || opts.Signer == nil || opts.Certificate == nil {
		return nil, errors.New("authentielf: signer and certificate are required")
	}
	if !publicKeyEqual(opts.Signer.Public(), opts.Certificate.PublicKey) {
		return nil, errors.New("authentielf: private key does not match certificate")
	}
	h := opts.Hash
	if h == 0 {
		h = crypto.SHA256
	}

	orig, err := Original(data)
	if err != nil {
		return nil, err
	}
	var existing []*Signature
	if opts.Append {
		existing, err = ReadSignatures(data)
		if err != nil && !errors.Is(err, ErrNotSigned) {
			return nil, err
		}
	}

	for i, s := range existing {
		d, err := digestOriginal(orig, s.HashAlgorithm)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(d, s.ImageDigest) {
			return nil, fmt.Errorf("authentielf: existing signature #%d does not match the file; sign without append to replace it", i)
		}
	}

	digest, err := digestOriginal(orig, h)
	if err != nil {
		return nil, err
	}
	content, err := encodeIndirectData(h, digest)
	if err != nil {
		return nil, err
	}
	sd := cms.New(OIDSpcIndirectData, content)
	attrs := []cms.Attribute{
		{Type: OIDSpcStatementType, Values: [][]byte{cms.Seq(cms.OID(OIDSpcIndividualSPKeyPur))}},
		{Type: OIDSpcSpOpusInfo, Values: [][]byte{encodeOpusInfo(opts.ProgramName, opts.MoreInfoURL)}},
	}
	if _, err := sd.AddSigner(opts.Signer, opts.Certificate, h, attrs); err != nil {
		return nil, fmt.Errorf("authentielf: %w", err)
	}
	sd.AddCertificates(opts.Intermediates...)
	sig, err := newSignature(sd)
	if err != nil {
		return nil, err
	}
	if opts.Timestamper != nil {
		if err := sig.addTimestamp(ctx, opts.Timestamper, h); err != nil {
			return nil, err
		}
	}
	return WriteSignatures(orig, append(existing, sig))
}

// addTimestamp requests a timestamp over the signature value and stores it
// as an RFC 3161 counter-signature (unsigned attribute 1.3.6.1.4.1.311.3.3.1),
// replacing any existing one.
func (s *Signature) addTimestamp(ctx context.Context, ts Timestamper, h crypto.Hash) error {
	if h == 0 {
		h = s.HashAlgorithm
	}
	hh := h.New()
	hh.Write(s.si.Signature)
	imprint := hh.Sum(nil)
	token, err := ts.Timestamp(ctx, h, imprint)
	if err != nil {
		return fmt.Errorf("authentielf: timestamp: %w", err)
	}
	tok, err := tsp.ParseToken(token)
	if err != nil {
		return fmt.Errorf("authentielf: timestamp: %w", err)
	}
	if tok.Info.HashAlgorithm != h || !bytes.Equal(tok.Info.HashedMessage, imprint) {
		return errors.New("authentielf: timestamp token does not cover the signature")
	}
	s.si.SetUnsignedAttr(OIDRFC3161Timestamp, [][]byte{token})
	return s.loadTimestamp()
}

// AddTimestamp timestamps the signature at index (or every signature when
// index is -1) using the signature's own digest algorithm, or h if non-zero.
func AddTimestamp(ctx context.Context, data []byte, index int, ts Timestamper, h crypto.Hash) ([]byte, error) {
	sigs, err := ReadSignatures(data)
	if err != nil {
		return nil, err
	}
	if index < -1 || index >= len(sigs) {
		return nil, fmt.Errorf("authentielf: signature index %d out of range (have %d)", index, len(sigs))
	}
	for i, s := range sigs {
		if index == -1 || index == i {
			if err := s.addTimestamp(ctx, ts, h); err != nil {
				return nil, fmt.Errorf("signature #%d: %w", i, err)
			}
		}
	}
	return WriteSignatures(data, sigs)
}

func publicKeyEqual(a, b crypto.PublicKey) bool {
	ka, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && ka.Equal(b)
}
