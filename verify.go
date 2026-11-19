package authentielf

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/jc-lab/authentielf/internal/cms"
)

// ErrDigestMismatch means the file contents do not match the signed digest.
var ErrDigestMismatch = errors.New("authentielf: image digest mismatch (file was modified after signing)")

// VerifyOptions configures Verify.
type VerifyOptions struct {
	// Roots are the trusted roots for code-signing chains. nil means the
	// system roots.
	Roots *x509.CertPool
	// TimestampRoots are the trusted roots for TSA chains. nil means Roots.
	TimestampRoots *x509.CertPool
	// CurrentTime is used for chain validation of signatures without a
	// valid timestamp. Zero means time.Now().
	CurrentTime time.Time
}

// VerifyResult is the outcome for one signature.
type VerifyResult struct {
	Index     int
	Signature *Signature
	// Chains are the verified code-signing chains.
	Chains [][]*x509.Certificate
	// TimestampChains are the verified TSA chains (when timestamped).
	TimestampChains [][]*x509.Certificate
	// VerifiedAt is the time the chain was validated at: the timestamp
	// time for timestamped signatures, otherwise the current time.
	VerifiedAt time.Time
	Err        error
}

// Verify verifies every signature in data. It returns per-signature
// results (when the signatures could be parsed) and a non-nil error unless
// the file is signed and all signatures are valid.
//
// The file must first be exactly the canonical layout of its original and
// signature blob (otherwise ErrNotCanonical). A signature is then valid when
// the image digest matches the original file, the PKCS#7
// signature is correct, the signer chains to a trusted root with the code
// signing EKU, and its timestamp (if any) is valid. With a valid timestamp
// the chain is validated at the timestamp time, so signatures outlive the
// expiry of the signing certificate.
func Verify(data []byte, opts *VerifyOptions) ([]*VerifyResult, error) {
	if opts == nil {
		opts = &VerifyOptions{}
	}
	c, err := openContainer(data)
	if err != nil {
		return nil, err
	}
	sigs, err := parseSignatures(c.pkcs7)
	if err != nil {
		return nil, err
	}
	digests := map[crypto.Hash][]byte{}
	var firstErr error
	results := make([]*VerifyResult, len(sigs))
	for i, s := range sigs {
		r := &VerifyResult{Index: i, Signature: s}
		r.Err = verifyOne(c.original, s, opts, digests, r)
		if r.Err != nil && firstErr == nil {
			firstErr = fmt.Errorf("signature #%d: %w", i, r.Err)
		}
		results[i] = r
	}
	return results, firstErr
}

func verifyOne(original []byte, s *Signature, opts *VerifyOptions, digests map[crypto.Hash][]byte, r *VerifyResult) error {
	d, ok := digests[s.HashAlgorithm]
	if !ok {
		var err error
		if d, err = digestOriginal(original, s.HashAlgorithm); err != nil {
			return err
		}
		digests[s.HashAlgorithm] = d
	}
	if !bytes.Equal(d, s.ImageDigest) {
		return ErrDigestMismatch
	}
	if h, err := cms.HashForOID(s.si.DigestAlgorithm.Algorithm); err != nil || h != s.HashAlgorithm {
		return errors.New("signer digest algorithm differs from image digest algorithm")
	}
	cert, err := s.sd.Verify(s.si)
	if err != nil {
		return err
	}

	r.VerifiedAt = opts.CurrentTime
	if r.VerifiedAt.IsZero() {
		r.VerifiedAt = time.Now()
	}
	if ts := s.Timestamp; ts != nil {
		hh := ts.HashAlgorithm.New()
		hh.Write(s.si.Signature)
		if !bytes.Equal(hh.Sum(nil), ts.token.Info.HashedMessage) {
			return errors.New("timestamp does not cover this signature")
		}
		tsRoots := opts.TimestampRoots
		if tsRoots == nil {
			tsRoots = opts.Roots
		}
		_, chains, err := ts.token.Verify(tsRoots)
		if err != nil {
			return fmt.Errorf("timestamp: %w", err)
		}
		r.TimestampChains = chains
		r.VerifiedAt = ts.Time
	}

	inter := x509.NewCertPool()
	for _, c := range s.sd.Certificates {
		inter.AddCert(c)
	}
	chains, err := cert.Verify(x509.VerifyOptions{
		Roots:         opts.Roots,
		Intermediates: inter,
		CurrentTime:   r.VerifiedAt,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	})
	if err != nil {
		return fmt.Errorf("certificate: %w", err)
	}
	r.Chains = chains
	return nil
}
