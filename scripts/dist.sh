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
