package authentielf

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jc-lab/authentielf/internal/testpki"
)

var (
	goBinOnce sync.Once
	goBin     []byte
	goBinErr  error
)

// sampleELF returns a freshly built static Go binary (built once per run).
func sampleELF(t *testing.T) []byte { return sampleELFTB(t) }

func sampleELFTB(t testing.TB) []byte {
	t.Helper()
	goBinOnce.Do(func() {
		dir, err := os.MkdirTemp("", "authentielf-test")
		if err != nil {
			goBinErr = err
			return
		}
		defer os.RemoveAll(dir)
		src := filepath.Join(dir, "main.go")
		os.WriteFile(src, []byte("package main\nfunc main() { println(\"signed hello\") }\n"), 0o644)
		out := filepath.Join(dir, "bin")
		cmd := exec.Command("go", "build", "-o", out, src)
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if b, err := cmd.CombinedOutput(); err != nil {
			goBinErr = errors.New(string(b))
			return
		}
		goBin, goBinErr = os.ReadFile(out)
	})
	if goBinErr != nil {
		t.Fatal(goBinErr)
	}
	return append([]byte(nil), goBin...)
}

func signWith(t *testing.T, data []byte, kp *testpki.KeyPair, p *testpki.PKI, h crypto.Hash, appendSig bool, ts Timestamper) []byte {
	t.Helper()
	out, err := Sign(context.Background(), data, &SignOptions{
		Signer: kp.Key, Certificate: kp.Cert,
		Intermediates: []*x509.Certificate{p.Intermediate.Cert},
		Hash:          h, Append: appendSig,
		ProgramName: "Test Program ✓", MoreInfoURL: "https://example.com/",
		Timestamper: ts,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return out
}

func mustVerify(t *testing.T, data []byte, p *testpki.PKI, want int) []*VerifyResult {
	t.Helper()
	res, err := Verify(data, &VerifyOptions{Roots: p.Roots()})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(res) != want {
		t.Fatalf("got %d signatures, want %d", len(res), want)
	}
	return res
}

func TestSignVerify(t *testing.T) {
	for _, kind := range []string{"rsa", "ecdsa"} {
		for _, h := range []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512} {
			t.Run(kind+"-"+h.String(), func(t *testing.T) {
				p := testpki.New(t, kind)
				signed := signWith(t, sampleELF(t), p.Leaf, p, h, false, nil)
				res := mustVerify(t, signed, p, 1)
				s := res[0].Signature
				if s.HashAlgorithm != h || s.ProgramName != "Test Program ✓" || s.MoreInfoURL != "https://example.com/" {
					t.Errorf("unexpected signature details: %v %q %q", s.HashAlgorithm, s.ProgramName, s.MoreInfoURL)
				}
				if !s.Signer.Equal(p.Leaf.Cert) {
					t.Error("wrong signer certificate")
				}
			})
		}
	}
}

func TestSignedBinaryRuns(t *testing.T) {
	p := testpki.New(t, "ecdsa")
	signed := signWith(t, sampleELF(t), p.Leaf, p, crypto.SHA256, false, nil)
	path := filepath.Join(t.TempDir(), "signed")
	os.WriteFile(path, signed, 0o755)
	out, err := exec.Command(path).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "signed hello") {
		t.Fatalf("signed binary failed: %v %q", err, out)
	}
}

func TestDigestEqualsOriginalHash(t *testing.T) {
	p := testpki.New(t, "rsa")
	orig := sampleELF(t)
	want := sha256.Sum256(orig)
	s1 := signWith(t, orig, p.Leaf, p, crypto.SHA256, false, nil)
	s2 := signWith(t, s1, p.Leaf, p, crypto.SHA384, true, nil)
	for i, d := range [][]byte{orig, s1, s2} {
		got, err := Digest(d, crypto.SHA256)
		if err != nil || !bytes.Equal(got, want[:]) {
			t.Fatalf("#%d: digest %x, want sha256(original) %x (err %v)", i, got, want, err)
		}
	}
	if len(s2) <= len(s1) {
		t.Error("appending a signature should grow the file by the signature size only")
	}
	// Removing every signature restores the original byte for byte.
	back, err := Original(s2)
	if err != nil || !bytes.Equal(back, orig) {
		t.Fatalf("Original() did not restore the input: %v", err)
	}
	none, err := RemoveSignature(s1, 0)
	if err != nil || !bytes.Equal(none, orig) {
		t.Fatalf("removing the last signature did not restore the input: %v", err)
	}
}

func TestMultipleSignatures(t *testing.T) {
	p := testpki.New(t, "rsa")
	q := testpki.New(t, "ecdsa")
	roots := p.Roots()
	roots.AddCert(q.Root.Cert)
	tsa := testpki.NewTSA(t, p.TSA)

	data := signWith(t, sampleELF(t), p.Leaf, p, crypto.SHA256, false, nil)
	data = signWith(t, data, q.Leaf, q, crypto.SHA384, true, NewRFC3161Timestamper(tsa.URL))
	data = signWith(t, data, p.Leaf, p, crypto.SHA512, true, nil)

	res, err := Verify(data, &VerifyOptions{Roots: roots})
	if err != nil {
		t.Fatal(err)
	}
	wantHash := []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512}
	for i, r := range res {
		if r.Signature.HashAlgorithm != wantHash[i] {
			t.Errorf("#%d: hash %v, want %v", i, r.Signature.HashAlgorithm, wantHash[i])
		}
		if (r.Signature.Timestamp != nil) != (i == 1) {
			t.Errorf("#%d: unexpected timestamp state", i)
		}
	}

	// Remove the primary: the first nested signature is promoted.
	data, err = RemoveSignature(data, 0)
	if err != nil {
		t.Fatal(err)
	}
	res, err = Verify(data, &VerifyOptions{Roots: roots})
	if err != nil || len(res) != 2 || res[0].Signature.HashAlgorithm != crypto.SHA384 || res[0].Signature.Timestamp == nil {
		t.Fatalf("after remove: err=%v n=%d", err, len(res))
	}

	// Replace (no append) drops all previous signatures.
	data = signWith(t, data, p.Leaf, p, crypto.SHA256, false, nil)
	mustVerify(t, data, p, 1)

	// Removing the last signature leaves a prepared but unsigned file.
	data, err = RemoveSignature(data, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(data, nil); !errors.Is(err, ErrNotSigned) {
		t.Fatalf("want ErrNotSigned, got %v", err)
	}
}

func TestTimestamp(t *testing.T) {
	p := testpki.New(t, "ecdsa")
	tsa := testpki.NewTSA(t, p.TSA)
	data := signWith(t, sampleELF(t), p.Leaf, p, crypto.SHA256, false, nil)

	data, err := AddTimestamp(context.Background(), data, -1, NewRFC3161Timestamper(tsa.URL), 0)
	if err != nil {
		t.Fatal(err)
	}
	res := mustVerify(t, data, p, 1)
	ts := res[0].Signature.Timestamp
	if ts == nil || time.Since(ts.Time) > time.Minute || len(res[0].TimestampChains) == 0 {
		t.Fatalf("bad timestamp: %+v", ts)
	}
	if !res[0].VerifiedAt.Equal(ts.Time) {
		t.Error("chain not validated at timestamp time")
	}

	// Long after the signing certificate expired, the timestamped
	// signature is still valid while an untimestamped one is not.
	future := time.Now().Add(3 * 365 * 24 * time.Hour)
	if _, err := Verify(data, &VerifyOptions{Roots: p.Roots(), CurrentTime: future}); err != nil {
		t.Fatalf("timestamped signature rejected after expiry: %v", err)
	}
	plain := signWith(t, sampleELF(t), p.Leaf, p, crypto.SHA256, false, nil)
	if _, err := Verify(plain, &VerifyOptions{Roots: p.Roots(), CurrentTime: future}); err == nil {
		t.Fatal("untimestamped signature accepted after expiry")
	}

	// A timestamp from an untrusted TSA invalidates the signature.
	other := testpki.New(t, "ecdsa")
	bad := testpki.NewTSA(t, other.TSA)
	data, err = AddTimestamp(context.Background(), data, 0, NewRFC3161Timestamper(bad.URL), 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(data, &VerifyOptions{Roots: p.Roots()}); err == nil || !strings.Contains(err.Error(), "timestamp") {
		t.Fatalf("untrusted TSA accepted: %v", err)
	}
}

func TestTamperDetection(t *testing.T) {
	p := testpki.New(t, "ecdsa")
	signed := signWith(t, sampleELF(t), p.Leaf, p, crypto.SHA256, false, nil)
	c, err := openContainer(signed)
	if err != nil {
		t.Fatal(err)
	}
	f, _ := parseELF(signed)
	sec := c.info.SectionOffset
	var aelf int
	for i, ph := range f.progs {
		if ph.Type == PT_AUTHENTIELF {
			aelf = i
		}
	}

	cases := map[string]struct {
		mutate func([]byte) []byte
		want   error // nil: any error
	}{
		"flip byte in code":           {func(d []byte) []byte { d[0x1000] ^= 1; return d }, ErrDigestMismatch},
		"flip byte in ELF header":     {func(d []byte) []byte { d[24] ^= 1; return d }, ErrNotCanonical}, // e_entry
		"flip byte in section header": {func(d []byte) []byte { d[f.hdr.Shoff+10] ^= 1; return d }, ErrNotCanonical},
		"flip byte in new phdr table": {func(d []byte) []byte { d[f.hdr.Phoff+uint64(aelf*f.phentsize())+4] ^= 2; return d }, ErrNotCanonical},
		"flip byte in note":           {func(d []byte) []byte { d[c.info.SectionOffset+c.info.SectionSize+30] ^= 1; return d }, nil},
		"append trailing data":        {func(d []byte) []byte { return append(d, "evil"...) }, ErrNotCanonical},
		"truncate":                    {func(d []byte) []byte { return d[:len(d)-1] }, nil},
		"grow entry length": {func(d []byte) []byte {
			binary.LittleEndian.PutUint32(d[sec:], binary.LittleEndian.Uint32(d[sec:])+1)
			return d
		}, nil},
		"corrupt PKCS#7": {func(d []byte) []byte { d[sec+EntryHeaderSize+100] ^= 1; return d }, nil},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			d := tc.mutate(append([]byte(nil), signed...))
			_, err := Verify(d, &VerifyOptions{Roots: p.Roots()})
			if err == nil {
				t.Fatal("tampered file verified")
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			t.Logf("rejected: %v", err)
		})
	}

	t.Run("objcopy add-section", func(t *testing.T) {
		objcopy, err := exec.LookPath("objcopy")
		if err != nil {
			t.Skip("objcopy not found")
		}
		dir := t.TempDir()
		in, extra, out := filepath.Join(dir, "in"), filepath.Join(dir, "extra"), filepath.Join(dir, "out")
		os.WriteFile(in, signed, 0o755)
		os.WriteFile(extra, []byte("payload"), 0o644)
		if b, err := exec.Command(objcopy, "--add-section", ".evil="+extra, in, out).CombinedOutput(); err != nil {
			t.Skipf("objcopy failed: %v %s", err, b)
		}
		d, _ := os.ReadFile(out)
		if _, err := Verify(d, &VerifyOptions{Roots: p.Roots()}); err == nil {
			t.Fatal("file with added section verified")
		} else {
			t.Logf("rejected: %v", err)
		}
	})
}

func TestTrustFailures(t *testing.T) {
	p := testpki.New(t, "rsa")
	other := testpki.New(t, "rsa")
	signed := signWith(t, sampleELF(t), p.Leaf, p, crypto.SHA256, false, nil)
	if _, err := Verify(signed, &VerifyOptions{Roots: other.Roots()}); err == nil {
		t.Fatal("untrusted root accepted")
	}
	// A certificate without the code-signing EKU must be rejected.
	wrongEKU := signWith(t, sampleELF(t), p.TSA, p, crypto.SHA256, false, nil)
	if _, err := Verify(wrongEKU, &VerifyOptions{Roots: p.Roots()}); err == nil {
		t.Fatal("TSA certificate accepted for code signing")
	}
	// Mismatched key/certificate.
	_, err := Sign(context.Background(), sampleELF(t), &SignOptions{Signer: other.Leaf.Key, Certificate: p.Leaf.Cert})
	if err == nil {
		t.Fatal("mismatched key accepted")
	}
}

func TestAppendToStaleSignatureRefused(t *testing.T) {
	p := testpki.New(t, "ecdsa")
	signed := signWith(t, sampleELF(t), p.Leaf, p, crypto.SHA256, false, nil)
	signed[0x1000] ^= 1
	_, err := Sign(context.Background(), signed, &SignOptions{Signer: p.Leaf.Key, Certificate: p.Leaf.Cert, Append: true})
	if err == nil {
		t.Fatal("append to stale signature accepted")
	}
}

func TestUnsigned(t *testing.T) {
	raw := sampleELF(t)
	if _, err := Verify(raw, nil); !errors.Is(err, ErrNotSigned) {
		t.Fatalf("want ErrNotSigned, got %v", err)
	}
	if _, err := Digest([]byte("not an elf"), crypto.SHA256); err == nil {
		t.Fatal("non-ELF accepted")
	}
	p := testpki.New(t, "ecdsa")
	if _, err := Sign(context.Background(), []byte("not an elf"), &SignOptions{Signer: p.Leaf.Key, Certificate: p.Leaf.Cert}); err == nil {
		t.Fatal("signed a non-ELF")
	}
}
