package main

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

func loadCerts(path string) ([]*x509.Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
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
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		// Accept a single DER certificate too.
		raw, _ := os.ReadFile(path)
		if c, err := x509.ParseCertificate(raw); err == nil {
			return []*x509.Certificate{c}, nil
		}
		return nil, fmt.Errorf("%s: no certificates found", path)
	}
	return certs, nil
}

func loadKey(path string) (crypto.Signer, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
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
