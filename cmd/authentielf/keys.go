package main

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jc-lab/authentielf/internal/gcpkms"
)

// Environment fallbacks for "sign" when -key-file / -cert-file are not
// given, so CI can pass a key and certificate chain without temporary
// files. For each, at most one of the _FILE and the text variable may be set.
const (
	envChainFile = "SIGN_CHAIN_FILE" // same as -chain-file
	envChain     = "SIGN_CHAIN"      // PEM text: additional intermediates
	envKeyFile   = "SIGN_KEY_FILE"   // same as -key-file: PEM key file or gcp-kms:// URI
	envKey       = "SIGN_KEY"        // PEM text of the private key
	envCertFile  = "SIGN_CERT_FILE"  // same as -cert-file
	envCert      = "SIGN_CERT"       // PEM text: signer certificate, then intermediates
)

// source is where a key or certificate comes from: a file (for keys, also
// a gcp-kms:// URI) or PEM text. name identifies it in errors.
type source struct{ file, text, name string }

// lookupSource picks the flag value if set, else $envFile or $envText; the
// zero source means none is set.
func lookupSource(flagVal, envFile, envText string) (source, error) {
	if flagVal != "" {
		return source{file: flagVal, name: flagVal}, nil
	}
	f, t := os.Getenv(envFile), os.Getenv(envText)
	switch {
	case f != "" && t != "":
		return source{}, fmt.Errorf("both $%s and $%s are set; use one", envFile, envText)
	case f != "":
		return source{file: f, name: f}, nil
	case t != "":
		return source{text: t, name: "$" + envText}, nil
	}
	return source{}, nil
}

// resolveSource is lookupSource for a required input.
func resolveSource(flagName, flagVal, envFile, envText string) (source, error) {
	src, err := lookupSource(flagVal, envFile, envText)
	if err == nil && src.name == "" {
		err = fmt.Errorf("-%s, $%s or $%s is required", flagName, envFile, envText)
	}
	return src, err
}

func (s source) read() ([]byte, error) {
	if s.file == "" {
		return []byte(s.text), nil
	}
	return os.ReadFile(s.file)
}

func loadCerts(path string) ([]*x509.Certificate, error) {
	return loadCertSource(source{file: path, name: path})
}

func loadCertSource(src source) ([]*x509.Certificate, error) {
	b, err := src.read()
	if err != nil {
		return nil, err
	}
	return parseCerts(b, src.name)
}

// parseCerts parses PEM certificates from b, or a single DER certificate.
// src names the input in errors.
func parseCerts(b []byte, src string) ([]*x509.Certificate, error) {
	raw := b
	var certs []*x509.Certificate
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", src, err)
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		// Accept a single DER certificate too.
		if c, err := x509.ParseCertificate(raw); err == nil {
			return []*x509.Certificate{c}, nil
		}
		return nil, fmt.Errorf("%s: no certificates found", src)
	}
	return certs, nil
}

func loadKey(src source) (crypto.Signer, error) {
	b, err := src.read()
	if err != nil {
		return nil, err
	}
	path := src.name
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			return nil, fmt.Errorf("%s: no private key found", path)
		}
		var k any
		switch blk.Type {
		case "PRIVATE KEY":
			k, err = x509.ParsePKCS8PrivateKey(blk.Bytes)
		case "RSA PRIVATE KEY":
			k, err = x509.ParsePKCS1PrivateKey(blk.Bytes)
		case "EC PRIVATE KEY":
			k, err = x509.ParseECPrivateKey(blk.Bytes)
		case "ENCRYPTED PRIVATE KEY":
			return nil, fmt.Errorf("%s: encrypted keys are not supported; decrypt with openssl first", path)
		default:
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		s, ok := k.(crypto.Signer)
		if !ok {
			return nil, errors.New("unsupported private key type")
		}
		return s, nil
	}
}

func publicKeyEqual(a, b crypto.PublicKey) bool {
	ka, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && ka.Equal(b)
}

const (
	kmsScheme   = "gcp-kms://"
	kmsTokenEnv = "GOOGLE_OAUTH_ACCESS_TOKEN"
)

// openKMS opens a Cloud KMS signer. For a crypto key (no version), the
// enabled version whose public key equals want, the signer certificate's,
// is used, so rotating the key and certificate together needs no change.
func openKMS(resource string, want crypto.PublicKey) (*gcpkms.Signer, error) {
	tok := strings.TrimSpace(os.Getenv(kmsTokenEnv))
	if tok == "" {
		return nil, fmt.Errorf("%s%s: set %s (e.g. $(gcloud auth print-access-token))", kmsScheme, resource, kmsTokenEnv)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	return (&gcpkms.Client{Token: tok}).Open(ctx, resource, want)
}
