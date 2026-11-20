// Package gcpkms is a crypto.Signer backed by a Google Cloud KMS asymmetric
// signing key, talking to the Cloud KMS REST API with the standard library
// only.
//
// Authentication is a plain OAuth 2.0 access token (for example from
// "gcloud auth print-access-token", or the access_token output of
// google-github-actions/auth with token_format: access_token); obtaining
// and refreshing it is left to the caller.
package gcpkms

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// DefaultEndpoint is the Cloud KMS REST API base URL.
const DefaultEndpoint = "https://cloudkms.googleapis.com/v1/"

var (
	keyRe     = regexp.MustCompile(`^projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+$`)
	versionRe = regexp.MustCompile(`^projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+/cryptoKeyVersions/[^/]+$`)
	crcTable  = crc32.MakeTable(crc32.Castagnoli)
)

// algorithms maps the Cloud KMS algorithms usable for Authenticode-style
// signatures (RSA PKCS#1 v1.5 and ECDSA) to the digest each one requires.
// RSA-PSS, raw PKCS#1, secp256k1 and the rest are rejected.
var algorithms = map[string]crypto.Hash{
	"RSA_SIGN_PKCS1_2048_SHA256": crypto.SHA256,
	"RSA_SIGN_PKCS1_3072_SHA256": crypto.SHA256,
	"RSA_SIGN_PKCS1_4096_SHA256": crypto.SHA256,
	"RSA_SIGN_PKCS1_4096_SHA512": crypto.SHA512,
	"EC_SIGN_P256_SHA256":        crypto.SHA256,
	"EC_SIGN_P384_SHA384":        crypto.SHA384,
}

// Client calls the Cloud KMS REST API.
type Client struct {
	Token    string       // OAuth 2.0 access token (required)
	Endpoint string       // default DefaultEndpoint
	HTTP     *http.Client // default: 30s timeout
	Timeout  time.Duration
}

// Signer signs digests with one Cloud KMS crypto key version.
type Signer struct {
	c         *Client
	name      string
	algorithm string
	hash      crypto.Hash
	pub       crypto.PublicKey
}

var _ crypto.Signer = (*Signer)(nil)

// Open returns a Signer for resource, which is either a crypto key version
// (".../cryptoKeys/K/cryptoKeyVersions/N") or a crypto key
// (".../cryptoKeys/K"). For a crypto key, the enabled version whose public
// key equals want is used; with want == nil the key must have exactly one
// enabled version. For a crypto key version, want (if non-nil) must match.
func (c *Client) Open(ctx context.Context, resource string, want crypto.PublicKey) (*Signer, error) {
	resource = strings.TrimPrefix(resource, "/")
	switch {
	case versionRe.MatchString(resource):
		s, err := c.openVersion(ctx, resource)
		if err != nil {
			return nil, err
		}
		if want != nil && !publicKeyEqual(s.pub, want) {
			return nil, fmt.Errorf("gcpkms: %s: public key does not match the certificate", resource)
		}
		return s, nil
	case keyRe.MatchString(resource):
		versions, err := c.enabledVersions(ctx, resource)
		if err != nil {
			return nil, err
		}
		if len(versions) == 0 {
			return nil, fmt.Errorf("gcpkms: %s has no enabled key versions", resource)
		}
		if want == nil {
			if len(versions) > 1 {
				return nil, fmt.Errorf("gcpkms: %s has %d enabled versions; name one explicitly", resource, len(versions))
			}
			return c.openVersion(ctx, versions[0])
		}
		var errs []error
		for _, v := range versions {
			s, err := c.openVersion(ctx, v)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			if publicKeyEqual(s.pub, want) {
				return s, nil
			}
		}
		errs = append(errs, fmt.Errorf("gcpkms: no enabled version of %s matches the certificate", resource))
		return nil, errors.Join(errs...)
	default:
		return nil, fmt.Errorf("gcpkms: %q is not a crypto key or crypto key version resource name", resource)
	}
}

func (c *Client) openVersion(ctx context.Context, name string) (*Signer, error) {
	var resp struct {
		Name      string `json:"name"`
		PEM       string `json:"pem"`
		PEMCRC32C int64s `json:"pemCrc32c"`
		Algorithm string `json:"algorithm"`
	}
	if err := c.call(ctx, http.MethodGet, name+"/publicKey", nil, &resp); err != nil {
		return nil, err
	}
	if resp.PEMCRC32C.set && int64(crc32.Checksum([]byte(resp.PEM), crcTable)) != resp.PEMCRC32C.v {
		return nil, fmt.Errorf("gcpkms: %s: public key CRC32C mismatch", name)
	}
	h, ok := algorithms[resp.Algorithm]
	if !ok {
		return nil, fmt.Errorf("gcpkms: %s: unsupported algorithm %s (need RSA_SIGN_PKCS1_* or EC_SIGN_P256/P384)", name, resp.Algorithm)
	}
	blk, _ := pem.Decode([]byte(resp.PEM))
	if blk == nil {
		return nil, fmt.Errorf("gcpkms: %s: malformed public key PEM", name)
	}
	pub, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("gcpkms: %s: %w", name, err)
	}
	return &Signer{c: c, name: name, algorithm: resp.Algorithm, hash: h, pub: pub}, nil
}

func (c *Client) enabledVersions(ctx context.Context, key string) ([]string, error) {
	var names []string
	token := ""
	for page := 0; page < 100; page++ {
		q := url.Values{"pageSize": {"100"}}
		if token != "" {
			q.Set("pageToken", token)
		}
		var resp struct {
			Versions []struct {
				Name  string `json:"name"`
				State string `json:"state"`
			} `json:"cryptoKeyVersions"`
			NextPageToken string `json:"nextPageToken"`
		}
		if err := c.call(ctx, http.MethodGet, key+"/cryptoKeyVersions?"+q.Encode(), nil, &resp); err != nil {
			return nil, err
		}
		for _, v := range resp.Versions {
			if v.State == "ENABLED" && versionRe.MatchString(v.Name) {
				names = append(names, v.Name)
			}
		}
		if token = resp.NextPageToken; token == "" {
			return names, nil
		}
	}
	return nil, fmt.Errorf("gcpkms: %s: too many key versions", key)
}

// Name is the crypto key version resource name.
func (s *Signer) Name() string { return s.name }

// Algorithm is the Cloud KMS algorithm, e.g. RSA_SIGN_PKCS1_3072_SHA256.
func (s *Signer) Algorithm() string { return s.algorithm }

// Hash is the digest algorithm the key version requires.
func (s *Signer) Hash() crypto.Hash { return s.hash }

// Public returns the key version's public key.
func (s *Signer) Public() crypto.PublicKey { return s.pub }

// Sign signs digest, which must have been computed with s.Hash(). rand is
// ignored. The returned signature is checked against the public key.
func (s *Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if _, pss := opts.(*rsa.PSSOptions); pss {
		return nil, errors.New("gcpkms: RSA-PSS is not supported")
	}
	if h := opts.HashFunc(); h != s.hash {
		return nil, fmt.Errorf("gcpkms: %s requires %v digests, got %v", s.algorithm, s.hash, h)
	}
	if len(digest) != s.hash.Size() {
		return nil, fmt.Errorf("gcpkms: digest is %d bytes, want %d", len(digest), s.hash.Size())
	}
	field := map[crypto.Hash]string{crypto.SHA256: "sha256", crypto.SHA384: "sha384", crypto.SHA512: "sha512"}[s.hash]
	req := map[string]any{
		"digest":       map[string]string{field: base64.StdEncoding.EncodeToString(digest)},
		"digestCrc32c": strconv.FormatUint(uint64(crc32.Checksum(digest, crcTable)), 10),
	}
	var resp struct {
		Name                 string `json:"name"`
		Signature            []byte `json:"signature"`
		SignatureCRC32C      int64s `json:"signatureCrc32c"`
		VerifiedDigestCRC32C bool   `json:"verifiedDigestCrc32c"`
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.c.timeout())
	defer cancel()
	if err := s.c.call(ctx, http.MethodPost, s.name+":asymmetricSign", req, &resp); err != nil {
		return nil, err
	}
	// End-to-end integrity checks recommended by Cloud KMS.
	if resp.Name != s.name {
		return nil, fmt.Errorf("gcpkms: response is for %q, want %q", resp.Name, s.name)
	}
	if !resp.VerifiedDigestCRC32C {
		return nil, errors.New("gcpkms: request corrupted in transit (digest CRC32C not verified)")
	}
	if !resp.SignatureCRC32C.set || int64(crc32.Checksum(resp.Signature, crcTable)) != resp.SignatureCRC32C.v {
		return nil, errors.New("gcpkms: response corrupted in transit (signature CRC32C mismatch)")
	}
	if err := verify(s.pub, s.hash, digest, resp.Signature); err != nil {
		return nil, fmt.Errorf("gcpkms: %s returned an invalid signature: %w", s.name, err)
	}
	return resp.Signature, nil
}

func verify(pub crypto.PublicKey, h crypto.Hash, digest, sig []byte) error {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(k, h, digest, sig)
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(k, digest, sig) {
			return errors.New("ECDSA verification failed")
		}
		return nil
	}
	return fmt.Errorf("unsupported public key %T", pub)
}

func (c *Client) timeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return 60 * time.Second
}

// call performs one API request, retrying briefly on rate limiting and
// transient server errors.
func (c *Client) call(ctx context.Context, method, path string, in, out any) error {
	if c.Token == "" {
		return errors.New("gcpkms: no access token")
	}
	endpoint := c.Endpoint
	if endpoint == "" {
		endpoint = DefaultEndpoint
	}
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	var body []byte
	if in != nil {
		var err error
		if body, err = json.Marshal(in); err != nil {
			return err
		}
	}
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(endpoint, "/")+"/"+path, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+c.Token)
		if in != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := hc.Do(req)
		if err != nil {
			return fmt.Errorf("gcpkms: %w", err)
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if err != nil {
			return fmt.Errorf("gcpkms: %w", err)
		}
		if resp.StatusCode == http.StatusOK {
			if err := json.Unmarshal(data, out); err != nil {
				return fmt.Errorf("gcpkms: decoding %s response: %w", path, err)
			}
			return nil
		}
		retry := resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
		if retry && attempt < 3 {
			select {
			case <-time.After(time.Duration(attempt+1) * time.Second):
				continue
			case <-ctx.Done():
				return fmt.Errorf("gcpkms: %w", ctx.Err())
			}
		}
		return apiError(resp.StatusCode, data)
	}
}

func apiError(status int, data []byte) error {
	var e struct {
		Error struct {
			Message string `json:"message"`
			Status  string `json:"status"`
		} `json:"error"`
	}
	if json.Unmarshal(data, &e) == nil && e.Error.Message != "" {
		return fmt.Errorf("gcpkms: %s (HTTP %d): %s", e.Error.Status, status, e.Error.Message)
	}
	return fmt.Errorf("gcpkms: HTTP %d", status)
}

// int64s decodes a protobuf Int64Value, which JSON encodes as a string.
type int64s struct {
	v   int64
	set bool
}

func (n *int64s) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "null" {
		return nil
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return err
	}
	n.v, n.set = v, true
	return nil
}

func publicKeyEqual(a, b crypto.PublicKey) bool {
	ka, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && ka.Equal(b)
}
