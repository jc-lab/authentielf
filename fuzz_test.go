package authentielf

import (
	"context"
	"crypto"
	"testing"

	"github.com/jc-lab/authentielf/internal/testpki"
)

// FuzzVerify checks that malformed files never cause a panic.
func FuzzVerify(f *testing.F) {
	p := testpki.New(f, "ecdsa")
	signed, err := Sign(context.Background(), sampleELFTB(f), &SignOptions{Signer: p.Leaf.Key, Certificate: p.Leaf.Cert})
	if err != nil {
		f.Fatal(err)
	}
	// Seed with the file head and the PKCS#7 blob, keeping inputs small.
	f.Add(signed[:4096])
	pk, _ := ReadPKCS7(signed)
	f.Add(pk)
	f.Fuzz(func(t *testing.T, b []byte) {
		Verify(b, nil)
		Original(b)
		parseSignatures(b)
		Digest(b, crypto.SHA256)
	})
}
