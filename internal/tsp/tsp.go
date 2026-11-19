// Package tsp implements an RFC 3161 Time-Stamp Protocol client and
// time-stamp token parsing/verification.
package tsp

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jc-lab/authentielf/internal/cms"
)

// OIDTSTInfo is id-ct-TSTInfo.
var OIDTSTInfo = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}

type messageImprint struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	HashedMessage []byte
}

type accuracy struct {
	Seconds int `asn1:"optional"`
	Millis  int `asn1:"optional,tag:0"`
	Micros  int `asn1:"optional,tag:1"`
}

type rawTSTInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint messageImprint
	SerialNumber   *big.Int
	GenTime        asn1.RawValue
	Accuracy       accuracy      `asn1:"optional"`
	Ordering       bool          `asn1:"optional,default:false"`
	Nonce          *big.Int      `asn1:"optional"`
	TSA            asn1.RawValue `asn1:"optional,tag:0"`
	Extensions     asn1.RawValue `asn1:"optional,tag:1"`
}

// Info is the parsed TSTInfo of a token.
type Info struct {
	Policy        asn1.ObjectIdentifier
	HashAlgorithm crypto.Hash
	HashedMessage []byte
	SerialNumber  *big.Int
	GenTime       time.Time
	Accuracy      time.Duration
	Nonce         *big.Int
}

// Token is a parsed RFC 3161 TimeStampToken.
type Token struct {
	Raw        []byte
	SignedData *cms.SignedData
	Info       Info
}

// ParseToken parses a DER TimeStampToken (a CMS ContentInfo).
func ParseToken(der []byte) (*Token, error) {
	sd, err := cms.Parse(der)
	if err != nil {
		return nil, fmt.Errorf("tsp: %w", err)
	}
	if !sd.ContentType.Equal(OIDTSTInfo) {
		return nil, fmt.Errorf("tsp: content type %v is not TSTInfo", sd.ContentType)
	}
	content, err := sd.ContentBytes()
	if err != nil {
		return nil, fmt.Errorf("tsp: %w", err)
	}
	var r rawTSTInfo
	rest, err := asn1.Unmarshal(content, &r)
	if err != nil || len(rest) != 0 {
		return nil, fmt.Errorf("tsp: malformed TSTInfo: %v", err)
	}
	if r.Version != 1 {
		return nil, fmt.Errorf("tsp: unsupported TSTInfo version %d", r.Version)
	}
	h, err := cms.HashForOID(r.MessageImprint.HashAlgorithm.Algorithm)
	if err != nil {
		return nil, fmt.Errorf("tsp: %w", err)
	}
	gt, err := parseGeneralizedTime(r.GenTime)
	if err != nil {
		return nil, err
	}
	return &Token{Raw: der, SignedData: sd, Info: Info{
		Policy:        r.Policy,
		HashAlgorithm: h,
		HashedMessage: r.MessageImprint.HashedMessage,
		SerialNumber:  r.SerialNumber,
		GenTime:       gt,
		Accuracy: time.Duration(r.Accuracy.Seconds)*time.Second +
			time.Duration(r.Accuracy.Millis)*time.Millisecond +
			time.Duration(r.Accuracy.Micros)*time.Microsecond,
		Nonce: r.Nonce,
	}}, nil
}

// parseGeneralizedTime parses YYYYMMDDHHMMSS[.f*]Z. encoding/asn1 rejects
// fractional seconds with trailing zeros, which some TSAs emit.
func parseGeneralizedTime(rv asn1.RawValue) (time.Time, error) {
	if rv.Class != asn1.ClassUniversal || rv.Tag != asn1.TagGeneralizedTime {
		return time.Time{}, errors.New("tsp: genTime is not a GeneralizedTime")
	}
	s := string(rv.Bytes)
	if !strings.HasSuffix(s, "Z") || len(s) < 15 {
		return time.Time{}, fmt.Errorf("tsp: invalid genTime %q", s)
	}
	s = strings.TrimSuffix(s, "Z")
	base, frac, hasFrac := strings.Cut(s, ".")
	t, err := time.Parse("20060102150405", base)
	if err != nil {
		return time.Time{}, fmt.Errorf("tsp: invalid genTime %q", s)
	}
	if hasFrac {
		if frac == "" || len(frac) > 9 {
			return time.Time{}, fmt.Errorf("tsp: invalid genTime fraction %q", frac)
		}
		n, err := strconv.Atoi(frac + strings.Repeat("0", 9-len(frac)))
		if err != nil {
			return time.Time{}, fmt.Errorf("tsp: invalid genTime fraction %q", frac)
		}
		t = t.Add(time.Duration(n))
	}
	return t.UTC(), nil
}

// Verify checks the token signature and the TSA certificate chain (with the
// timeStamping EKU) at the token's genTime. It returns the TSA certificate
// and the verified chains.
func (t *Token) Verify(roots *x509.CertPool) (*x509.Certificate, [][]*x509.Certificate, error) {
	if len(t.SignedData.Signers) != 1 {
		return nil, nil, errors.New("tsp: token must have exactly one signer")
	}
	cert, err := t.SignedData.Verify(t.SignedData.Signers[0])
	if err != nil {
		return nil, nil, fmt.Errorf("tsp: %w", err)
	}
	inter := x509.NewCertPool()
	for _, c := range t.SignedData.Certificates {
		inter.AddCert(c)
	}
	chains, err := cert.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
		CurrentTime:   t.Info.GenTime,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	})
	if err != nil {
		return cert, nil, fmt.Errorf("tsp: TSA certificate: %w", err)
	}
	return cert, chains, nil
}

// Signer returns the TSA certificate, if it is embedded in the token.
func (t *Token) Signer() *x509.Certificate {
	if len(t.SignedData.Signers) == 0 {
		return nil
	}
	return t.SignedData.FindCertificate(t.SignedData.Signers[0])
}

// CreateRequest encodes a TimeStampReq with certReq=TRUE.
func CreateRequest(h crypto.Hash, digest []byte, nonce *big.Int) ([]byte, error) {
	oid, err := cms.OIDForHash(h)
	if err != nil {
		return nil, err
	}
	parts := [][]byte{
		cms.MustMarshal(1),
		cms.Seq(cms.AlgorithmIdentifier(oid, true), cms.OctetString(digest)),
	}
	if nonce != nil {
		parts = append(parts, cms.MustMarshal(nonce))
	}
	parts = append(parts, []byte{0x01, 0x01, 0xff}) // certReq BOOLEAN TRUE
	return cms.Seq(parts...), nil
}

type pkiStatusInfo struct {
	Status       int
	StatusString []string       `asn1:"optional"`
	FailInfo     asn1.BitString `asn1:"optional"`
}

type timeStampResp struct {
	Status         pkiStatusInfo
	TimeStampToken asn1.RawValue `asn1:"optional"`
}

// ParseResponse parses a TimeStampResp and returns the token DER.
func ParseResponse(der []byte) ([]byte, error) {
	var r timeStampResp
	rest, err := asn1.Unmarshal(der, &r)
	if err != nil || len(rest) != 0 {
		return nil, fmt.Errorf("tsp: malformed response: %v", err)
	}
	if r.Status.Status != 0 && r.Status.Status != 1 { // granted, grantedWithMods
		return nil, fmt.Errorf("tsp: request rejected (status %d) %s", r.Status.Status, strings.Join(r.Status.StatusString, "; "))
	}
	if len(r.TimeStampToken.FullBytes) == 0 {
		return nil, errors.New("tsp: response has no token")
	}
	return r.TimeStampToken.FullBytes, nil
}

// Client requests timestamps from an RFC 3161 HTTP endpoint.
type Client struct {
	URL        string
	HTTPClient *http.Client // nil: a client with a 30s timeout
}

// Timestamp obtains a token over digest (the hash of the data, computed
// with h) and checks that the token answers this request.
func (c *Client) Timestamp(ctx context.Context, h crypto.Hash, digest []byte) ([]byte, error) {
	nonceBytes := make([]byte, 8)
	if _, err := rand.Read(nonceBytes); err != nil {
		return nil, err
	}
	nonce := new(big.Int).SetBytes(nonceBytes)
	req, err := CreateRequest(h, digest, nonce)
	if err != nil {
		return nil, err
	}
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, bytes.NewReader(req))
	if err != nil {
		return nil, err
	}
	hreq.Header.Set("Content-Type", "application/timestamp-query")
	hc := c.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := hc.Do(hreq)
	if err != nil {
		return nil, fmt.Errorf("tsp: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tsp: HTTP %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("tsp: %w", err)
	}
	der, err := ParseResponse(body)
	if err != nil {
		return nil, err
	}
	tok, err := ParseToken(der)
	if err != nil {
		return nil, err
	}
	if tok.Info.HashAlgorithm != h || !bytes.Equal(tok.Info.HashedMessage, digest) {
		return nil, errors.New("tsp: token message imprint does not match request")
	}
	if tok.Info.Nonce == nil || tok.Info.Nonce.Cmp(nonce) != 0 {
		return nil, errors.New("tsp: token nonce does not match request")
	}
	return der, nil
}
