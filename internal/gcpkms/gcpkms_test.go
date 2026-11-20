package gcpkms_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"hash/crc32"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/jc-lab/authentielf"
	"github.com/jc-lab/authentielf/internal/gcpkms"
	"github.com/jc-lab/authentielf/internal/testpki"
)

const keyName = "projects/p/locations/l/keyRings/r/cryptoKeys/k"

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

type fakeVersion struct {
	key       crypto.Signer
	algorithm string
	state     string
}

// fakeKMS emulates the three Cloud KMS endpoints the signer uses.
type fakeKMS struct {
	t        *testing.T
	versions map[string]*fakeVersion // by version id
	order    []string
	corrupt  bool // flip a signature byte
	signs    int
}

func (f *fakeKMS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer tok" {
		http.Error(w, `{"error":{"message":"bad token","status":"UNAUTHENTICATED"}}`, 401)
		return
	}
	p := strings.TrimPrefix(r.URL.Path, "/v1/")
	reply := func(v any) { json.NewEncoder(w).Encode(v) }
	ver := func(name string) *fakeVersion {
		id := name[strings.LastIndex(name, "/")+1:]
		if !strings.HasPrefix(name, keyName+"/cryptoKeyVersions/") || f.versions[id] == nil {
			http.Error(w, `{"error":{"message":"not found","status":"NOT_FOUND"}}`, 404)
			return nil
		}
		return f.versions[id]
	}
	switch {
	case r.Method == "GET" && p == keyName+"/cryptoKeyVersions":
		var list []map[string]string
		for _, id := range f.order {
			list = append(list, map[string]string{"name": keyName + "/cryptoKeyVersions/" + id, "state": f.versions[id].state})
		}
		reply(map[string]any{"cryptoKeyVersions": list})
	case r.Method == "GET" && strings.HasSuffix(p, "/publicKey"):
		name := strings.TrimSuffix(p, "/publicKey")
		v := ver(name)
		if v == nil {
			return
		}
		der, _ := x509.MarshalPKIXPublicKey(v.key.Public())
		pemText := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
		reply(map[string]any{"name": name, "pem": pemText, "algorithm": v.algorithm,
			"pemCrc32c": strconv.FormatUint(uint64(crc32.Checksum([]byte(pemText), castagnoli)), 10)})
	case r.Method == "POST" && strings.HasSuffix(p, ":asymmetricSign"):
		name := strings.TrimSuffix(p, ":asymmetricSign")
		v := ver(name)
		if v == nil {
			return
		}
		var req struct {
			Digest       map[string][]byte `json:"digest"`
			DigestCRC32C string            `json:"digestCrc32c"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Digest) != 1 {
			http.Error(w, `{"error":{"message":"bad request","status":"INVALID_ARGUMENT"}}`, 400)
			return
		}
		var h crypto.Hash
		var digest []byte
		for k, d := range req.Digest {
			h = map[string]crypto.Hash{"sha256": crypto.SHA256, "sha384": crypto.SHA384, "sha512": crypto.SHA512}[k]
			digest = d
		}
		sig, err := v.key.Sign(rand.Reader, digest, h)
		if err != nil {
			f.t.Errorf("fake sign: %v", err)
		}
		f.signs++
		if f.corrupt {
			sig[0] ^= 1
		}
		reply(map[string]any{"name": name, "signature": sig,
			"signatureCrc32c":      strconv.FormatUint(uint64(crc32.Checksum(sig, castagnoli)), 10),
			"verifiedDigestCrc32c": req.DigestCRC32C == strconv.FormatUint(uint64(crc32.Checksum(digest, castagnoli)), 10)})
	default:
		http.Error(w, `{"error":{"message":"unexpected","status":"NOT_FOUND"}}`, 404)
	}
}

func newFake(t *testing.T) (*fakeKMS, *gcpkms.Client) {
	f := &fakeKMS{t: t, versions: map[string]*fakeVersion{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, &gcpkms.Client{Token: "tok", Endpoint: srv.URL + "/v1/"}
}

func (f *fakeKMS) add(id string, key crypto.Signer, alg, state string) {
	f.versions[id] = &fakeVersion{key, alg, state}
	f.order = append(f.order, id)
}

func TestOpenSelectsVersionByCertificate(t *testing.T) {
	f, c := newFake(t)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	f.add("1", other, "RSA_SIGN_PKCS1_2048_SHA256", "ENABLED")
	f.add("2", rsaKey, "RSA_SIGN_PKCS1_2048_SHA256", "DISABLED")
	f.add("3", ecKey, "EC_SIGN_P384_SHA384", "ENABLED")
	f.add("4", rsaKey, "RSA_SIGN_PKCS1_2048_SHA256", "ENABLED")
	ctx := context.Background()

	s, err := c.Open(ctx, keyName, rsaKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	if s.Name() != keyName+"/cryptoKeyVersions/4" || s.Hash() != crypto.SHA256 {
		t.Fatalf("got %s %v", s.Name(), s.Hash())
	}
	d := sha256.Sum256([]byte("hello"))
	sig, err := s.Sign(nil, d[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if err := rsa.VerifyPKCS1v15(&rsaKey.PublicKey, crypto.SHA256, d[:], sig); err != nil {
		t.Fatal(err)
	}

	s, err = c.Open(ctx, keyName, ecKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	d384 := sha512.Sum384([]byte("hello"))
	sig, err = s.Sign(nil, d384[:], crypto.SHA384)
	if err != nil || !ecdsa.VerifyASN1(&ecKey.PublicKey, d384[:], sig) {
		t.Fatalf("ecdsa sign: %v", err)
	}
	if _, err := s.Sign(nil, d[:], crypto.SHA256); err == nil {
		t.Fatal("SHA-256 digest accepted by a SHA-384 key")
	}

	// Explicit versions.
	if _, err := c.Open(ctx, keyName+"/cryptoKeyVersions/4", rsaKey.Public()); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Open(ctx, keyName+"/cryptoKeyVersions/1", rsaKey.Public()); err == nil {
		t.Fatal("version with a different key accepted")
	}
	// Ambiguous without a certificate; no match at all.
	if _, err := c.Open(ctx, keyName, nil); err == nil {
		t.Fatal("ambiguous key accepted")
	}
	stranger, _ := rsa.GenerateKey(rand.Reader, 2048)
	if _, err := c.Open(ctx, keyName, stranger.Public()); err == nil {
		t.Fatal("unmatched certificate accepted")
	}
}

func TestOpenRejects(t *testing.T) {
	f, c := newFake(t)
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	f.add("1", k, "RSA_SIGN_PSS_2048_SHA256", "ENABLED")
	ctx := context.Background()
	for _, name := range []string{
		keyName + "/cryptoKeyVersions/1",             // PSS
		"projects/p/locations/l/keyRings/r",          // not a key
		keyName + "/cryptoKeyVersions/1/../../other", // path tricks
		"https://evil.example/" + keyName,
	} {
		if _, err := c.Open(ctx, name, nil); err == nil {
			t.Errorf("Open(%q) succeeded", name)
		}
	}
	bad := *c
	bad.Token = "wrong"
	if _, err := bad.Open(ctx, keyName, nil); err == nil || !strings.Contains(err.Error(), "UNAUTHENTICATED") {
		t.Errorf("bad token: %v", err)
	}
}

func TestCorruptSignatureRejected(t *testing.T) {
	f, c := newFake(t)
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	f.add("1", k, "RSA_SIGN_PKCS1_2048_SHA256", "ENABLED")
	s, err := c.Open(context.Background(), keyName, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.corrupt = true
	d := sha256.Sum256(nil)
	if _, err := s.Sign(nil, d[:], crypto.SHA256); err == nil {
		t.Fatal("corrupt signature accepted")
	}
}

// TestSignELF signs a real ELF through the fake KMS and verifies it.
func TestSignELF(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	data, err := os.ReadFile(exe)
	if err != nil || len(data) < 4 || string(data[:4]) != "\x7fELF" {
		t.Skip("test binary is not ELF")
	}
	for _, kind := range []string{"rsa", "ecdsa"} {
		t.Run(kind, func(t *testing.T) {
			p := testpki.New(t, kind)
			f, c := newFake(t)
			alg := "RSA_SIGN_PKCS1_2048_SHA256"
			if kind == "ecdsa" {
				alg = "EC_SIGN_P256_SHA256"
			}
			f.add("7", p.Leaf.Key, alg, "ENABLED")
			s, err := c.Open(context.Background(), keyName, p.Leaf.Cert.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			signed, err := authentielf.Sign(context.Background(), data, &authentielf.SignOptions{
				Signer: s, Certificate: p.Leaf.Cert,
				Intermediates: []*x509.Certificate{p.Intermediate.Cert}, Hash: s.Hash(),
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := authentielf.Verify(signed, &authentielf.VerifyOptions{Roots: p.Roots()}); err != nil {
				t.Fatal(err)
			}
			if f.signs != 1 {
				t.Fatalf("%d KMS sign calls, want 1", f.signs)
			}
		})
	}
}
