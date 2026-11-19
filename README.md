# AuthentiELF

Authenticode-style code signing for ELF binaries, in Go.

An AuthentiELF signature is a PKCS#7 `SignedData` with the same structure
as a Windows Authenticode PE signature: `SpcIndirectDataContent`, nested
signatures and RFC 3161 timestamps. Only two things differ:

- The image data type is `SPC_ELF_IMAGE_DATA_OBJID_V1`
  (`1.3.6.1.4.1.62615.1001.1.21`).
- The image digest is **the hash of the original, unsigned file**. A file
  has the same digest before and after signing, so `authentielf digest app`
  equals `sha256sum app` of the unsigned binary.

## Install

Download a prebuilt static binary from
[Releases](https://github.com/jc-lab/authentielf/releases). Builds are
available for these platforms:

| OS | Architectures |
|---|---|
| Linux | `amd64`, `386`, `arm64`, `armv7`, `armv6`, `riscv64`, `ppc64`, `ppc64le`, `s390x`, `loong64`, `mips-softfloat`, `mipsle-softfloat`, `mips64`, `mips64le` |
| macOS | `amd64`, `arm64` |
| Windows | `amd64`, `arm64` |

The CLI can sign ELF files on any of these platforms. To install a release
on Linux:

```sh
V=v1.0.0 A=linux_amd64
curl -LO https://github.com/jc-lab/authentielf/releases/download/$V/authentielf_${V}_${A}.tar.gz
curl -LO https://github.com/jc-lab/authentielf/releases/download/$V/SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS
tar -xzf authentielf_${V}_${A}.tar.gz && sudo install authentielf_${V}_${A}/authentielf /usr/local/bin/
```

Or build from source with `go install github.com/jc-lab/authentielf/cmd/authentielf@latest`.

### Verifying a release

Every archive has a [SLSA build provenance](https://slsa.dev/provenance)
attestation. It is signed through Sigstore and records the repository,
the tag, the commit and the workflow run that built the archive. Check it
with the GitHub CLI:

```sh
gh attestation verify authentielf_${V}_${A}.tar.gz --repo jc-lab/authentielf \
  --signer-workflow jc-lab/authentielf/.github/workflows/release.yml
```

This proves that the archive was built by this repository's release
workflow. The `SHA256SUMS` check alone only proves that the file matches
the published list.

### Releasing

Push a tag of the form `vMAJOR.MINOR.PATCH`. A tag with a suffix, such as
`v1.2.0-rc.1`, publishes a pre-release. On a tag push,
[`release.yml`](.github/workflows/release.yml) does the following:

1. Runs the full CI matrix.
2. Builds the archives with `make dist VERSION=<tag>`
   ([`scripts/dist.sh`](scripts/dist.sh)).
3. Runs the native e2e suite against the shipped `linux_amd64` binary.
4. Creates build provenance attestations for every archive in `SHA256SUMS`
   (`actions/attest`) and verifies one with `gh attestation verify`.
5. Publishes a GitHub release with the archives, `SHA256SUMS` and generated
   notes.

The builds are reproducible: `-trimpath`, and archive metadata pinned to the
commit time. Running `make dist VERSION=<tag>` on the tagged commit gives
identical checksums.

## CLI

```sh
authentielf sign -cert signer.pem -key signer.key [-hash sha256] [-t http://timestamp.digicert.com] app
authentielf sign -append -hash sha512 -cert other.pem -key other.key app   # add a second signature
authentielf verify [-ca root.pem] [-tsa-ca tsa-root.pem] app              # exit 0 = all signatures valid
authentielf show app                                                      # inspect without trust checks
authentielf timestamp -t URL [-index N] app
authentielf remove -index N app
authentielf remove -all -o app.orig app                                   # restore the original byte for byte
authentielf extract [-index N] [-pem] -o sig.p7b app
authentielf digest [-hash sha256] app
```

Files are modified in place unless `-o` is given. `-cert` may contain the
signer certificate followed by intermediates. Keys must be unencrypted PEM
(PKCS#8, PKCS#1 or SEC1); RSA and ECDSA are supported.

`verify` uses the system roots by default. `-ca` replaces them for
code-signing chains, and the TSA chain is then checked against the system
roots plus `-ca`, so a private code-signing CA works with a public TSA.

## Library

```go
signed, err := authentielf.Sign(ctx, data, &authentielf.SignOptions{
	Signer: key, Certificate: cert, Intermediates: chain,
	Hash: crypto.SHA256, Append: false,
	Timestamper: authentielf.NewRFC3161Timestamper("http://timestamp.digicert.com"),
})
results, err := authentielf.Verify(signed, &authentielf.VerifyOptions{Roots: roots})
```

Other entry points: `Digest`, `Original`, `IsSigned`, `Inspect`,
`ReadSignatures`, `WriteSignatures`, `RemoveSignature`, `AddTimestamp`,
`ReadPKCS7` and `WritePKCS7`.

## Format

### Signed file = layout(original, PKCS#7)

A signed file is a deterministic function of the original file and the
PKCS#7 blob. Every byte of the original stays where it was. Five ELF header
fields are patched (`e_phoff`, `e_phnum`, `e_shoff`, `e_shnum`,
`e_shstrndx`), and a tail is appended:

```
[original file, header fields patched]
[zero padding — legacy placement only, see below]
[new program header table   ] <- e_phoff, PT_PHDR        \  new PT_LOAD
[.authentielf  (signature)  ] <- PT_AUTHENTIELF          /  (PF_R)
[.note.authentielf          ]    original ELF header + original size
[.shstrtab                  ]    old table + the two new names
[section header table       ] <- e_shoff: old entries + the two new ones
```

- **`.authentielf`** has type `SHT_PROGBITS` and flag `SHF_ALLOC`. It is
  sized to the signature (8-byte aligned, at most 1 MiB) and is loaded into
  memory by a new read-only `PT_LOAD`. This segment is inserted after the
  last existing `PT_LOAD`, at a vaddr above all of them.
- **`PT_AUTHENTIELF`** (`0x61656c66`, "aelf", in PT_LOOS..PT_HIOS) points
  exactly at the section. Section headers are not mapped at runtime, so this
  is how a running program finds its signature (`dl_iterate_phdr`/`AT_PHDR`).
- **`.note.authentielf`** is a non-alloc `SHT_NOTE`: name `AuthentiELF`,
  type 1. Its descriptor, in the ELF's byte order, is
  `u32 version (1)`, `u32 reserved (0)`, `u64 original size`, followed by the
  original ELF header.

The file grows by the signature plus about 1 KB of headers. Two signatures
with a timestamp add about 20 KB to `/bin/ls`.

### Section contents

Modelled on `WIN_CERTIFICATE`:

```
offset 0  u32 LE  length  = 6 + len(PKCS#7)
offset 4  u16 LE  version = 1
offset 6  PKCS#7 SignedData (DER)
...       zero padding to a multiple of 8
```

### Image digest and verification

```
digest = H(original file)
```

The verifier works in four steps:

1. Read the original ELF header and size from `.note.authentielf`.
2. Rebuild the original: `original = saved header || file[ehsize : original size]`.
3. Recompute `layout(original, pkcs7)`, then require the file to be
   **exactly** that, byte for byte. Otherwise it fails with
   `ErrNotCanonical`.
4. Verify every signature against `H(original)`.

`layout` has no free parameters, so the PKCS#7 blob is the only part of a
signed file that can change without detection. That is the same guarantee
Authenticode gives for its certificate table, but stricter: data appended
after the signature is rejected too.

- Adding, replacing or removing signatures and timestamps keeps the digest.
  Signatures can therefore be added one after another, each with its own
  digest algorithm.
- Any other change is rejected, including:
  - patching code or headers (`ErrDigestMismatch` / `ErrNotCanonical`)
  - appending data
  - adding a section (e.g. `objcopy --add-section`)
  - stripping
  - editing the note
- `remove -all` and `Original()` return the original file byte for byte.

Hashing everything except the new phdr/shdr entries would not be enough:
the program header table has to move (there is no room in place), and
`PT_PHDR`, the ELF header and `.shstrtab` change with it. Leaving those out
of the hash would leave the headers the loader actually uses unprotected.
Rebuilding the original and requiring the canonical layout covers all of
them.

To be signable, the original must not reference bytes past its own end,
whether through a segment or a section. After signing, those bytes would be
the appended tail.

### Segment placement and older kernels

Linux before 5.18 computes `AT_PHDR` as `load_addr + e_phoff`, using the
first `PT_LOAD` (glibc's ld.so and static glibc read the program headers
from there). qemu-user does the same. To stay compatible, layout uses
**legacy placement** when it can: the new segment gets
`vaddr - offset = (first PT_LOAD).vaddr - offset`.

Legacy placement needs zero padding whenever the memory image (bss) reaches
past the end of the file. Some measured cases:

| Binary | Padding |
|---|---|
| `/bin/ls` | 9 KiB |
| `bash`, `libc.so.6` | about 44 KiB |
| stripped cgo binary | 214 KiB |

If more than `MaxLegacyPadding` (256 KiB) would be needed, layout uses
**compact placement** instead: the segment goes directly after the original
with an independent vaddr and no padding. A compact-placed dynamic or
static-glibc binary needs Linux ≥ 5.18. Static Go binaries do not read
`AT_PHDR` and run anywhere. `authentielf show` reports which placement was
used.

### PKCS#7 structure

As in Authenticode:

- `ContentInfo{signedData}` → `SignedData` v1 with exactly one `SignerInfo`
  v1 (issuerAndSerialNumber).
- The content type is `SPC_INDIRECT_DATA_OBJID` (`1.3.6.1.4.1.311.2.1.4`).
  The content is embedded PKCS#7-v1.5 style as
  `[0] EXPLICIT SpcIndirectDataContent`, not wrapped in an OCTET STRING:
  ```
  SpcIndirectDataContent ::= SEQUENCE {
      data           SEQUENCE { type OBJECT IDENTIFIER (1.3.6.1.4.1.62615.1001.1.21) },
      messageDigest  DigestInfo  -- H(original file)
  }
  ```
- The signed attributes are `contentType`, `messageDigest`,
  `SPC_STATEMENT_TYPE` (individual) and `SPC_SP_OPUS_INFO` (program name and
  more-info URL). `messageDigest` covers the content octets of
  `SpcIndirectDataContent`, without its tag and length.
- Supported digests are SHA-256 (default), SHA-384, SHA-512 and SHA-1. The
  signer's digest algorithm must equal the image digest algorithm.
- **Multiple signatures** are stored as values of the unsigned attribute
  `szOID_NESTED_SIGNATURE` (`1.3.6.1.4.1.311.2.4.1`) of the primary signer,
  as `signtool /as` does.
- **Timestamps** are RFC 3161 `TimeStampToken`s in the unsigned attribute
  `1.3.6.1.4.1.311.3.3.1`, with the imprint taken over the signature value.
  The legacy countersignature (`1.2.840.113549.1.9.6`) is not supported.

A signature is valid when all of these hold:

1. The image digest matches.
2. The CMS signature and the signed attributes are correct.
3. The timestamp, if present, is valid and its TSA chain is trusted for
   `timeStamping`.
4. The signer chains to a trusted root with `codeSigning`. The chain is
   checked at the timestamp time if there is one, otherwise now.

`Verify` succeeds only if **all** signatures are valid.

## Testing

```sh
make test                                   # gofmt/vet, go test, native e2e
make e2e E2E_TARGETS="native aarch64 s390x" # selected e2e targets
make deps E2E_TARGETS=all && make e2e E2E_TARGETS=all STRICT=1   # full matrix (Ubuntu 24.04)
make fuzz FUZZTIME=60s
```

[`test/e2e.sh`](test/e2e.sh) builds sample binaries for each target:

| Target | Samples |
|---|---|
| `native` | C PIE, non-PIE, static, static-PIE, shared library, big-bss; Go static, cgo, PIE |
| `aarch64` `armhf` `i686` `riscv64` `s390x` `ppc64` `mips` | C PIE, non-PIE, static, shared library (cross gcc); static Go. Run under `qemu-<arch>` |

For every binary the script:

1. Signs it: RSA/SHA-256 with a timestamp from an OpenSSL-backed TSA
   ([`test/tsa.py`](test/tsa.py)), then appends an ECDSA/SHA-384 signature.
2. Verifies it, and checks that `digest == sha256(original)` and that
   `readelf` reports no new warnings.
3. Runs it and compares the output with the original's.
4. Checks that a flipped byte and appended data are both detected.
5. Checks that `remove -all` restores the original exactly.

Because qemu-user computes `AT_PHDR` the way pre-5.18 kernels do, the cross
targets also exercise legacy placement. CI
([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) runs each target as
a separate job.
