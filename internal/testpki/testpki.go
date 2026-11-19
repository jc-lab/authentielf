// Package testpki builds throw-away PKIs and an in-process RFC 3161 TSA for
// tests. It must not be used outside tests.
package testpki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jc-lab/authentielf/internal/cms"
)

// KeyPair is a certificate with its private key.
type KeyPair struct {
	Cert *x509.Certificate
	Key  crypto.Signer
}

var serial atomic.Int64

// Template returns a certificate template valid from notBefore to notAfter.
func Template(cn string, notBefore, notAfter time.Time) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(1000 + serial.Add(1)),
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"AuthentiELF Test"}},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
}

// NewKey returns a fresh key: "rsa" (2048) or "ecdsa" (P-256).
func NewKey(t testing.TB, kind string) crypto.Signer {
	t.Helper()
	var k crypto.Signer
	var err error
	switch kind {
	case "rsa":
		k, err = rsa.GenerateKey(rand.Reader, 2048)
	default:
		k, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// Issue creates a certificate from tmpl for key, signed by parent (nil =
// self-signed).
func Issue(t testing.TB, tmpl *x509.Certificate, key crypto.Signer, parent *KeyPair) *KeyPair {
	t.Helper()
	pc, pk := tmpl, key
	if parent != nil {
		pc, pk = parent.Cert, parent.Key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, pc, key.Public(), pk)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &KeyPair{Cert: c, Key: key}
}

// PKI is a root CA, an intermediate, a code-signing leaf and a TSA.
type PKI struct {
	Root, Intermediate, Leaf, TSA *KeyPair
}

// New builds a PKI whose leaf uses the given key kind.
func New(t testing.TB, leafKind string) *PKI {
	t.Helper()
	now := time.Now()
	ca := func(cn string) *x509.Certificate {
		c := Template(cn, now.Add(-24*time.Hour), now.Add(10*365*24*time.Hour))
		c.IsCA, c.BasicConstraintsValid = true, true
		c.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		return c
	}
	p := &PKI{}
	p.Root = Issue(t, ca("Test Root"), NewKey(t, "ecdsa"), nil)
	p.Intermediate = Issue(t, ca("Test Intermediate"), NewKey(t, "ecdsa"), p.Root)

	leaf := Template("Test Code Signer", now.Add(-time.Hour), now.Add(365*24*time.Hour))
	leaf.KeyUsage = x509.KeyUsageDigitalSignature
	leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
	p.Leaf = Issue(t, leaf, NewKey(t, leafKind), p.Intermediate)

	tsa := Template("Test TSA", now.Add(-24*time.Hour), now.Add(10*365*24*time.Hour))
	tsa.KeyUsage = x509.KeyUsageDigitalSignature
	tsa.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}
	p.TSA = Issue(t, tsa, NewKey(t, "rsa"), p.Root)
	return p
}

// Roots returns a pool containing only the root CA.
func (p *PKI) Roots() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(p.Root.Cert)
	return pool
}

type messageImprint struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	HashedMessage []byte
}

type timeStampReq struct {
	Version        int
	MessageImprint messageImprint
	ReqPolicy      asn1.ObjectIdentifier `asn1:"optional"`
	Nonce          *big.Int              `asn1:"optional"`
	CertReq        bool                  `asn1:"optional,default:false"`
}

// TSAServer starts an RFC 3161 TSA signing with tsa. Now, if non-nil,
// overrides the genTime.
type TSAServer struct {
	*httptest.Server
	Requests atomic.Int64
	Now      func() time.Time
}

// NewTSA starts a test TSA; it is closed when the test ends.
func NewTSA(t testing.TB, tsa *KeyPair) *TSAServer {
	t.Helper()
	s := &TSAServer{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.Requests.Add(1)
		body, _ := io.ReadAll(r.Body)
		var req timeStampReq
		if _, err := asn1.Unmarshal(body, &req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		now := time.Now()
		if s.Now != nil {
			now = s.Now()
		}
		tst := cms.Seq(
			cms.MustMarshal(1),
			cms.OID(asn1.ObjectIdentifier{1, 2, 3, 4}),
			cms.Seq(cms.AlgorithmIdentifier(req.MessageImprint.HashAlgorithm.Algorithm, true), cms.OctetString(req.MessageImprint.HashedMessage)),
			cms.MustMarshal(big.NewInt(serial.Add(1))),
			// Fractional seconds with a trailing zero, as some real TSAs emit.
			cms.TLV(asn1.TagGeneralizedTime, []byte(now.UTC().Format("20060102150405")+".120Z")),
			cms.MustMarshal(req.Nonce),
		)
		sd := cms.New(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}, cms.OctetString(tst))
		sd.Version = 3
		if _, err := sd.AddSigner(tsa.Key, tsa.Cert, crypto.SHA256, nil); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		resp := cms.Seq(cms.Seq(cms.MustMarshal(0)), sd.Encode())
		w.Header().Set("Content-Type", "application/timestamp-reply")
		w.Write(resp)
	}))
	t.Cleanup(s.Close)
	return s
}
