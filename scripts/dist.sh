#!/usr/bin/env bash
# Cross-compile the authentielf CLI and package one archive per OS/arch.
#
# Usage: scripts/dist.sh <version> [outdir]
#
# Produces <outdir>/authentielf_<version>_<os>_<arch>.tar.gz (.zip on
# Windows), each containing the binary, LICENSE and README.md, plus
# <outdir>/SHA256SUMS. Builds are static (CGO_ENABLED=0) and reproducible:
# -trimpath, no VCS stamping, and archive metadata pinned to the commit
# time (SOURCE_DATE_EPOCH).
#
# Optional signing, enabled by SIGN_KEY_FILE or SIGN_KEY:
#   Linux (ELF)  AuthentiELF, with the CLI built from this tree
#   Windows (PE) Authenticode, with jsign via scripts/sign-pe.sh ($JSIGN)
#   macOS        not signed
# Both read the key and certificates from the environment:
#   SIGN_KEY_FILE   private key PEM file, or gcp-kms://<Cloud KMS key resource>
#                   (token in $GOOGLE_OAUTH_ACCESS_TOKEN)
#   SIGN_KEY        private key PEM text
#   SIGN_CERT_FILE  signer certificate followed by intermediates (PEM file)
#   SIGN_CERT       the same as PEM text
#   SIGN_CHAIN_FILE / SIGN_CHAIN  extra intermediates (optional)
#   SIGN_TSA        RFC 3161 timestamp server URL (optional)
# Signed archives are not bit-for-bit reproducible (signing and timestamp
# times). For Linux, "authentielf remove -all" on a shipped binary yields
# exactly the reproducible unsigned build, and "authentielf digest" is its
# SHA-256; the macOS archives stay reproducible.
set -euo pipefail

VERSION=${1:?usage: dist.sh <version> [outdir]}
OUT=$(realpath -m "${2:-build/dist}")
GO=${GO:-go}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

# os/arch[/variant]: variant is GOARM for arm, GOMIPS for mips*.
TARGETS=(
	linux/amd64 linux/386 linux/arm64 linux/arm/7 linux/arm/6
	linux/riscv64 linux/ppc64 linux/ppc64le linux/s390x linux/loong64
	linux/mips/softfloat linux/mipsle/softfloat linux/mips64 linux/mips64le
	darwin/amd64 darwin/arm64
	windows/amd64 windows/arm64
)

for tool in zip tar gzip sha256sum; do
	command -v "$tool" >/dev/null || { echo "dist.sh: $tool is required" >&2; exit 1; }
done

: "${SOURCE_DATE_EPOCH:=$(git log -1 --format=%ct 2>/dev/null || date +%s)}"
export SOURCE_DATE_EPOCH

case $OUT in /*/*) ;; *) echo "refusing outdir $OUT" >&2; exit 2 ;; esac
rm -rf "${OUT:?}"
mkdir -p "$OUT"
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT

sign=${SIGN_KEY_FILE:-${SIGN_KEY:-}}
if [ -n "$sign" ]; then
	if [ -z "${SIGN_CERT_FILE:-}${SIGN_CERT:-}" ]; then
		echo "dist.sh: SIGN_CERT_FILE or SIGN_CERT is required for signing" >&2
		exit 1
	fi
	read -ra jsign <<<"${JSIGN:-jsign}"
	command -v "${jsign[0]}" >/dev/null ||
		{ echo "dist.sh: ${jsign[0]} (\$JSIGN) is required to sign Windows binaries" >&2; exit 1; }
	signer=$stage/.authentielf-host
	env -u GOOS -u GOARCH -u GOARM -u GOMIPS CGO_ENABLED=0 "$GO" build -trimpath -o "$signer" ./cmd/authentielf
	elf_args=(sign -n authentielf)
	if [ -n "${SIGN_TSA:-}" ]; then elf_args+=(-t "$SIGN_TSA"); fi
fi

# retry runs a signing command, retrying transient KMS/TSA failures. Both
# signers replace the previous attempt's signature, so a retry is idempotent.
retry() {
	for i in 1 2 3; do
		"$@" >&2 && return 0
		echo "dist.sh: '$*' failed (attempt $i)" >&2
		sleep $((i * 5))
	done
	return 1
}

for t in "${TARGETS[@]}"; do
	IFS=/ read -r os arch variant <<<"$t"
	name=$arch
	env=(CGO_ENABLED=0 GOOS="$os" GOARCH="$arch")
	case $arch in
	arm) env+=(GOARM="$variant") name=armv$variant ;;
	mips | mipsle) env+=(GOMIPS="$variant") name=$arch-$variant ;;
	esac
	exe=authentielf
	[ "$os" = windows ] && exe=authentielf.exe
	base=authentielf_${VERSION}_${os}_${name}
	dir=$stage/$base
	mkdir -p "$dir"
	echo "building $base" >&2
	env "${env[@]}" "$GO" build -trimpath -buildvcs=false \
		-ldflags "-s -w -buildid= -X main.version=$VERSION" \
		-o "$dir/$exe" ./cmd/authentielf
	if [ -n "$sign" ]; then
		case $os in
		linux) retry "$signer" "${elf_args[@]}" "$dir/$exe" ;;
		windows) SIGN_NAME=authentielf retry "$ROOT/scripts/sign-pe.sh" "$dir/$exe" ;;
		esac
	fi
	cp LICENSE README.md "$dir/"
	touch -d "@$SOURCE_DATE_EPOCH" "$dir" "$dir"/*
	if [ "$os" = windows ]; then
		# Members listed explicitly in sorted order (zip -r follows
		# directory order, which is not reproducible).
		(cd "$stage" && LC_ALL=C find "$base" | LC_ALL=C sort | zip -qX -@ "$OUT/$base.zip")
	else
		tar -C "$stage" --sort=name --owner=0 --group=0 --numeric-owner \
			--mtime="@$SOURCE_DATE_EPOCH" -cf - "$base" | gzip -9n >"$OUT/$base.tar.gz"
	fi
done

(cd "$OUT" && sha256sum -- *.tar.gz *.zip >SHA256SUMS)
echo "wrote $(ls "$OUT" | wc -l) files to $OUT" >&2
