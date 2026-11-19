// Command authentielf signs, verifies and inspects AuthentiELF signatures.
package main

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/jc-lab/authentielf"
)

const usage = `usage: authentielf <command> [flags] <file>

Commands:
  sign       sign an ELF file (replace or -append signatures)
  verify     verify all signatures
  show       print signatures without checking trust (alias: info)
  timestamp  add an RFC 3161 timestamp to existing signature(s)
  remove     remove one or all signatures (-all restores the original file)
  extract    write the PKCS#7 signature blob to a file
  digest     print the image digest (= hash of the original, unsigned file)
  version    print the CLI version

Run "authentielf <command> -h" for command flags.
`

// version is set at release build time with -ldflags "-X main.version=...".
var version = ""

func versionString() string {
	v := version
	if v == "" {
		v = "dev"
		if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
			v = bi.Main.Version // go install ...@vX.Y.Z
		}
	}
	return fmt.Sprintf("authentielf %s (%s, %s/%s)", v, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmds := map[string]func([]string) error{
		"sign":      cmdSign,
		"verify":    cmdVerify,
		"show":      cmdShow,
		"info":      cmdShow,
		"timestamp": cmdTimestamp,
		"remove":    cmdRemove,
		"extract":   cmdExtract,
		"digest":    cmdDigest,
	}
	name := os.Args[1]
	switch name {
	case "-h", "--help", "help":
		fmt.Print(usage)
		return
	case "version", "-version", "--version":
		fmt.Println(versionString())
		return
	}
	fn, ok := cmds[name]
	if !ok {
		fmt.Fprintf(os.Stderr, "authentielf: unknown command %q\n\n%s", name, usage)
		os.Exit(2)
	}
	if err := fn(os.Args[2:]); err != nil {
		var ee exitError
		if errors.As(err, &ee) {
			os.Exit(int(ee))
		}
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		fmt.Fprintf(os.Stderr, "authentielf %s: %v\n", name, err)
		os.Exit(1)
	}
}

type exitError int

func (e exitError) Error() string { return fmt.Sprintf("exit status %d", int(e)) }

// parse parses flags interleaved with exactly one positional file argument.
func parse(fs *flag.FlagSet, args []string) (string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return "", err
		}
		args = fs.Args()
		if len(args) == 0 {
			break
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
	if len(pos) != 1 {
		fs.Usage()
		return "", exitError(2)
	}
	return pos[0], nil
}

func newFlagSet(name, args string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "usage: authentielf %s [flags] %s\n", name, args)
		fs.PrintDefaults()
	}
	return fs
}

func parseHash(s string) (crypto.Hash, error) {
	switch strings.ToLower(strings.ReplaceAll(s, "-", "")) {
	case "", "default":
		return 0, nil
	case "sha1":
		return crypto.SHA1, nil
	case "sha256":
		return crypto.SHA256, nil
	case "sha384":
		return crypto.SHA384, nil
	case "sha512":
		return crypto.SHA512, nil
	}
	return 0, fmt.Errorf("unknown hash %q (sha1, sha256, sha384, sha512)", s)
}

// writeFile atomically replaces path, keeping the original file mode.
func writeFile(path string, data []byte, like string) error {
	mode := os.FileMode(0o755)
	if st, err := os.Stat(like); err == nil {
		mode = st.Mode().Perm()
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func outputPath(out, in string) string {
	if out != "" {
		return out
	}
	return in
}

func cmdSign(args []string) error {
	fs := newFlagSet("sign", "<file>")
	certFile := fs.String("cert", "", "PEM certificate file: signer certificate, optionally followed by intermediates (required)")
	keyFile := fs.String("key", "", "PEM private key file (PKCS#8, PKCS#1 or SEC1) (required)")
	chainFile := fs.String("chain", "", "additional PEM file with intermediate certificates")
	hashName := fs.String("hash", "sha256", "digest algorithm: sha256, sha384, sha512, sha1")
	appendSig := fs.Bool("append", false, "add as an additional (nested) signature instead of replacing existing ones")
	tsURL := fs.String("t", "", "RFC 3161 timestamp server URL")
	name := fs.String("n", "", "program name (SpcSpOpusInfo)")
	moreInfo := fs.String("u", "", "more-info URL (SpcSpOpusInfo)")
	out := fs.String("o", "", "output file (default: sign in place)")
	file, err := parse(fs, args)
	if err != nil {
		return err
	}
	if *certFile == "" || *keyFile == "" {
		fs.Usage()
		return exitError(2)
	}
	h, err := parseHash(*hashName)
	if err != nil {
		return err
	}
	key, err := loadKey(*keyFile)
	if err != nil {
		return err
	}
	certs, err := loadCerts(*certFile)
	if err != nil {
		return err
	}
	if *chainFile != "" {
		more, err := loadCerts(*chainFile)
		if err != nil {
			return err
		}
		certs = append(certs, more...)
	}
	var leaf *x509.Certificate
	var inter []*x509.Certificate
	for _, c := range certs {
		if leaf == nil && publicKeyEqual(key.Public(), c.PublicKey) {
			leaf = c
			continue
		}
		inter = append(inter, c)
	}
	if leaf == nil {
		return errors.New("no certificate matches the private key")
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	opts := &authentielf.SignOptions{
		Signer: key, Certificate: leaf, Intermediates: inter,
		Hash: h, Append: *appendSig,
		ProgramName: *name, MoreInfoURL: *moreInfo,
	}
	if *tsURL != "" {
		opts.Timestamper = authentielf.NewRFC3161Timestamper(*tsURL)
	}
	signed, err := authentielf.Sign(context.Background(), data, opts)
	if err != nil {
		return err
	}
	dst := outputPath(*out, file)
	if err := writeFile(dst, signed, file); err != nil {
		return err
	}
	sigs, _ := authentielf.ReadSignatures(signed)
	fmt.Printf("Signed %s (%d signature(s))\n", dst, len(sigs))
	return nil
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func cmdVerify(args []string) error {
	fs := newFlagSet("verify", "<file>")
	var cas multiFlag
	fs.Var(&cas, "ca", "trusted code-signing root certificates (PEM); repeatable. Default: system roots")
	var tsaCAs multiFlag
	fs.Var(&tsaCAs, "tsa-ca", "trusted TSA root certificates (PEM); repeatable. Default: system roots plus -ca")
	at := fs.String("time", "", "validate untimestamped signatures at this time (RFC 3339) instead of now")
	quiet := fs.Bool("q", false, "print nothing; report the result only through the exit status")
	file, err := parse(fs, args)
	if err != nil {
		return err
	}
	opts := &authentielf.VerifyOptions{}
	if len(cas) > 0 {
		if opts.Roots, err = loadPool(x509.NewCertPool(), cas); err != nil {
			return err
		}
		// Public TSAs chain to system roots even when code signing uses a
		// private CA.
		sys, err := x509.SystemCertPool()
		if err != nil {
			sys = x509.NewCertPool()
		}
		if opts.TimestampRoots, err = loadPool(sys, cas); err != nil {
			return err
		}
	}
	if len(tsaCAs) > 0 {
		if opts.TimestampRoots, err = loadPool(x509.NewCertPool(), tsaCAs); err != nil {
			return err
		}
	}
	if *at != "" {
		if opts.CurrentTime, err = time.Parse(time.RFC3339, *at); err != nil {
			return err
		}
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	results, verr := authentielf.Verify(data, opts)
	if *quiet {
		if verr != nil {
			return exitError(1)
		}
		return nil
	}
	for _, r := range results {
		s := r.Signature
		status := "OK"
		if r.Err != nil {
			status = "FAILED: " + r.Err.Error()
		}
		fmt.Printf("Signature #%d: %s\n", r.Index, status)
		fmt.Printf("  Signer:    %s\n", subject(s.Signer))
		fmt.Printf("  Digest:    %s %s\n", s.HashAlgorithm, hex.EncodeToString(s.ImageDigest))
		if s.Timestamp != nil {
			fmt.Printf("  Timestamp: %s (TSA: %s)\n", s.Timestamp.Time.Format(time.RFC3339), subject(s.Timestamp.Signer))
		}
		if len(r.Chains) > 0 {
			fmt.Printf("  Chain:     %s\n", chainString(r.Chains[0]))
		}
	}
	if verr != nil {
		if len(results) == 0 {
			fmt.Printf("Verification FAILED: %v\n", verr)
		} else {
			fmt.Println("Verification FAILED")
		}
		return exitError(1)
	}
	fmt.Printf("Verification OK: %d signature(s) valid\n", len(results))
	return nil
}

func loadPool(pool *x509.CertPool, files []string) (*x509.CertPool, error) {
	for _, f := range files {
		certs, err := loadCerts(f)
		if err != nil {
			return nil, err
		}
		for _, c := range certs {
			pool.AddCert(c)
		}
	}
	return pool, nil
}

func subject(c *x509.Certificate) string {
	if c == nil {
		return "(certificate not embedded)"
	}
	return c.Subject.String()
}

func chainString(chain []*x509.Certificate) string {
	names := make([]string, len(chain))
	for i, c := range chain {
		names[i] = c.Subject.CommonName
		if names[i] == "" {
			names[i] = c.Subject.String()
		}
	}
	return strings.Join(names, " -> ")
}

func cmdShow(args []string) error {
	fs := newFlagSet("show", "<file>")
	file, err := parse(fs, args)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	fmt.Printf("File:       %s\n", file)
	info, err := authentielf.Inspect(data)
	if errors.Is(err, authentielf.ErrNotSigned) {
		fmt.Println("Signatures: none")
		return nil
	} else if err != nil {
		return err
	}
	placement := "compact (requires Linux >= 5.18 for dynamic/static-glibc binaries)"
	if info.Legacy {
		placement = fmt.Sprintf("legacy-compatible, %d bytes padding", info.Padding)
	}
	fmt.Printf("Original:   %d bytes (signed file adds %d)\n", info.OriginalSize, uint64(len(data))-info.OriginalSize)
	fmt.Printf("Section:    %s at offset 0x%x, vaddr 0x%x, size %d\n", authentielf.SectionName, info.SectionOffset, info.SectionVaddr, info.SectionSize)
	fmt.Printf("Placement:  %s\n", placement)
	p7, err := authentielf.ReadPKCS7(data)
	if err != nil {
		return err
	}
	sigs, err := authentielf.ReadSignatures(data)
	if err != nil {
		return err
	}
	fmt.Printf("PKCS#7:     %d bytes (max %d)\n", len(p7), authentielf.MaxPKCS7Size)
	fmt.Printf("Signatures: %d\n", len(sigs))
	digests := map[crypto.Hash]string{}
	for i, s := range sigs {
		kind := "nested"
		if i == 0 {
			kind = "primary"
		}
		cur, ok := digests[s.HashAlgorithm]
		if !ok {
			d, err := authentielf.Digest(data, s.HashAlgorithm)
			if err == nil {
				cur = hex.EncodeToString(d)
			}
			digests[s.HashAlgorithm] = cur
		}
		match := "MISMATCH (file modified)"
		if cur == hex.EncodeToString(s.ImageDigest) {
			match = "matches file"
		}
		fmt.Printf("\nSignature #%d (%s)\n", i, kind)
		fmt.Printf("  Digest algorithm: %s\n", s.HashAlgorithm)
		fmt.Printf("  Image digest:     %s (%s)\n", hex.EncodeToString(s.ImageDigest), match)
		if c := s.Signer; c != nil {
			fmt.Printf("  Signer:           %s\n", c.Subject)
			fmt.Printf("  Issuer:           %s\n", c.Issuer)
			fmt.Printf("  Serial:           %s\n", c.SerialNumber.Text(16))
			fmt.Printf("  Validity:         %s - %s\n", c.NotBefore.Format(time.RFC3339), c.NotAfter.Format(time.RFC3339))
			fmt.Printf("  Key:              %s\n", c.PublicKeyAlgorithm)
		} else {
			fmt.Printf("  Signer:           (certificate not embedded)\n")
		}
		if s.ProgramName != "" {
			fmt.Printf("  Program name:     %s\n", s.ProgramName)
		}
		if s.MoreInfoURL != "" {
			fmt.Printf("  More info:        %s\n", s.MoreInfoURL)
		}
		fmt.Printf("  Certificates:     %d embedded\n", len(s.Certificates))
		for _, c := range s.Certificates {
			fmt.Printf("    - %s\n", c.Subject)
		}
		if ts := s.Timestamp; ts != nil {
			fmt.Printf("  Timestamp:        %s (%s, TSA: %s)\n", ts.Time.Format(time.RFC3339Nano), ts.HashAlgorithm, subject(ts.Signer))
		} else {
			fmt.Printf("  Timestamp:        none\n")
		}
	}
	return nil
}

func cmdTimestamp(args []string) error {
	fs := newFlagSet("timestamp", "<file>")
	tsURL := fs.String("t", "", "RFC 3161 timestamp server URL (required)")
	index := fs.Int("index", -1, "signature index to timestamp (-1: all)")
	hashName := fs.String("hash", "", "imprint digest algorithm (default: the signature's)")
	out := fs.String("o", "", "output file (default: in place)")
	file, err := parse(fs, args)
	if err != nil {
		return err
	}
	if *tsURL == "" {
		fs.Usage()
		return exitError(2)
	}
	h, err := parseHash(*hashName)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	res, err := authentielf.AddTimestamp(context.Background(), data, *index, authentielf.NewRFC3161Timestamper(*tsURL), h)
	if err != nil {
		return err
	}
	dst := outputPath(*out, file)
	if err := writeFile(dst, res, file); err != nil {
		return err
	}
	fmt.Printf("Timestamped %s\n", dst)
	return nil
}

func cmdRemove(args []string) error {
	fs := newFlagSet("remove", "<file>")
	index := fs.Int("index", -1, "signature index to remove")
	all := fs.Bool("all", false, "remove all signatures, restoring the original unsigned file byte for byte")
	out := fs.String("o", "", "output file (default: in place)")
	file, err := parse(fs, args)
	if err != nil {
		return err
	}
	if *all == (*index >= 0) {
		return errors.New("specify exactly one of -index N or -all")
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	var res []byte
	if *all {
		res, err = authentielf.Original(data)
	} else {
		res, err = authentielf.RemoveSignature(data, *index)
	}
	if err != nil {
		return err
	}
	dst := outputPath(*out, file)
	if err := writeFile(dst, res, file); err != nil {
		return err
	}
	sigs, _ := authentielf.ReadSignatures(res)
	fmt.Printf("Updated %s (%d signature(s) left)\n", dst, len(sigs))
	return nil
}

func cmdExtract(args []string) error {
	fs := newFlagSet("extract", "<file>")
	out := fs.String("o", "", "output file (default: stdout)")
	index := fs.Int("index", -1, "extract only this signature (without nested ones); -1: the whole blob")
	asPEM := fs.Bool("pem", false, "PEM output (\"PKCS7\")")
	file, err := parse(fs, args)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	var der []byte
	if *index < 0 {
		der, err = authentielf.ReadPKCS7(data)
	} else {
		var sigs []*authentielf.Signature
		if sigs, err = authentielf.ReadSignatures(data); err == nil {
			if *index >= len(sigs) {
				return fmt.Errorf("signature index %d out of range (have %d)", *index, len(sigs))
			}
			der = sigs[*index].Encode()
		}
	}
	if err != nil {
		return err
	}
	if *asPEM {
		der = pem.EncodeToMemory(&pem.Block{Type: "PKCS7", Bytes: der})
	}
	var w io.Writer = os.Stdout
	if *out != "" {
		return os.WriteFile(*out, der, 0o644)
	}
	_, err = w.Write(der)
	return err
}

func cmdDigest(args []string) error {
	fs := newFlagSet("digest", "<file>")
	hashName := fs.String("hash", "sha256", "digest algorithm")
	file, err := parse(fs, args)
	if err != nil {
		return err
	}
	h, err := parseHash(*hashName)
	if err != nil {
		return err
	}
	if h == 0 {
		h = crypto.SHA256
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	note := ""
	if authentielf.IsSigned(data) {
		note = "  (original, unsigned file)"
	}
	d, err := authentielf.Digest(data, h)
	if err != nil {
		return err
	}
	fmt.Printf("%s  %s%s\n", hex.EncodeToString(d), file, note)
	return nil
}
