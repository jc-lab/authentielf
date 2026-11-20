#!/usr/bin/env bash
# End-to-end test of the authentielf CLI on real binaries.
#
# For every sample (static/dynamic, PIE/non-PIE, shared library, Go, across
# architectures) it:
#   1. signs with RSA/SHA-256 + RFC 3161 timestamp (openssl-backed TSA) and
#      appends an ECDSA/SHA-384 signature
#   2. verifies against the test root
#   3. checks digest == sha256(original) and readelf reports no problems
#   4. runs the signed binary (natively or under qemu-user) and compares the
#      output with the original's
#   5. checks that tampering (flipped byte, appended data) is detected
#   6. checks that `remove -all` restores the original byte for byte
#
# Usage: test/e2e.sh [native|aarch64|armhf|i686|riscv64|s390x|ppc64|mips|all]...
# Env:   AUTHENTIELF  path to the CLI (required)
#        OUT          work directory (default build/e2e)
#        STRICT=1     a missing toolchain/emulator is a failure, not a skip
set -euo pipefail

log() { printf '%s\n' "$*" >&2; }

AELF=$(realpath "${AUTHENTIELF:?set AUTHENTIELF to the authentielf binary}")
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=$(realpath -m "${OUT:-build/e2e}")
STRICT=${STRICT:-0}

ALL_TARGETS=(native aarch64 armhf i686 riscv64 s390x ppc64 mips)
targets=("$@")
[ ${#targets[@]} -eq 0 ] && targets=(native)
[ "${targets[0]}" = all ] && targets=("${ALL_TARGETS[@]}")

declare -A TRIPLE=(
	[aarch64]=aarch64-linux-gnu [armhf]=arm-linux-gnueabihf [i686]=i686-linux-gnu
	[riscv64]=riscv64-linux-gnu [s390x]=s390x-linux-gnu [ppc64]=powerpc64-linux-gnu
	[mips]=mips-linux-gnu)
declare -A QEMU=(
	[aarch64]=qemu-aarch64 [armhf]=qemu-arm [i686]=qemu-i386 [riscv64]=qemu-riscv64
	[s390x]=qemu-s390x [ppc64]=qemu-ppc64 [mips]=qemu-mips)
declare -A GOARCH_OF=(
	[aarch64]=arm64 [armhf]=arm [i686]=386 [riscv64]=riscv64 [s390x]=s390x
	[ppc64]=ppc64 [mips]=mips)

case $OUT in /* ) ;; *) log "bad OUT=$OUT"; exit 2 ;; esac
[ "$OUT" != / ] && [ "$OUT" != "$HOME" ] || { log "refusing OUT=$OUT"; exit 2; }
rm -rf "${OUT:?}"
mkdir -p "$OUT"
REPORT=$OUT/report.txt
: >"$REPORT"
pass=0 fail=0 skip=0

record() { # status target sample detail
	printf '%-5s %-8s %-14s %s\n' "$1" "$2" "$3" "$4" | tee -a "$REPORT"
	case $1 in PASS) pass=$((pass + 1)) ;; FAIL) fail=$((fail + 1)) ;; SKIP) skip=$((skip + 1)) ;; esac
}
missing() { # target what
	if [ "$STRICT" = 1 ]; then record FAIL "$1" - "missing $2"; else record SKIP "$1" - "missing $2"; fi
}

# --- PKI and TSA -------------------------------------------------------------
setup_pki() {
	local d=$OUT/pki
	mkdir -p "$d"
	(
		cd "$d"
		issue() { # name key-algo signer extensions subject
			local name=$1 algo=$2 signer=$3 ext=$4 subj=$5
			if [ "$algo" = rsa ]; then
				openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$name.key" 2>/dev/null
			else
				openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$name.key" 2>/dev/null
			fi
			openssl req -new -key "$name.key" -subj "$subj" -out "$name.csr" 2>/dev/null
			printf '%b\n' "$ext" >"$name.ext"
			if [ "$signer" = self ]; then
				openssl x509 -req -in "$name.csr" -signkey "$name.key" -days 3650 \
					-extfile "$name.ext" -out "$name.pem" 2>/dev/null
			else
				openssl x509 -req -in "$name.csr" -CA "$signer.pem" -CAkey "$signer.key" \
					-set_serial "0x$(openssl rand -hex 8)" -days 365 \
					-extfile "$name.ext" -out "$name.pem" 2>/dev/null
			fi
		}
		ca='basicConstraints=critical,CA:true\nkeyUsage=critical,keyCertSign,cRLSign'
		issue root ec self "$ca" "/CN=AuthentiELF E2E Root"
		issue inter ec root "$ca" "/CN=AuthentiELF E2E Intermediate"
		cs='basicConstraints=CA:false\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=codeSigning'
		issue signer1 rsa inter "$cs" "/CN=E2E RSA Signer"
		issue signer2 ec root "$cs" "/CN=E2E ECDSA Signer"
		issue tsa rsa root 'basicConstraints=CA:false\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=critical,timeStamping' "/CN=E2E TSA"
		cat signer1.pem inter.pem >signer1-chain.pem
		cat >ts.cnf <<-EOF
			[ tsa ]
			default_tsa = tsa_config
			[ tsa_config ]
			serial = $d/tsaserial
			signer_digest = sha256
			default_policy = 1.2.3.4.1
			digests = sha1, sha256, sha384, sha512
			accuracy = secs:1
			ess_cert_id_alg = sha256
		EOF
		echo 01 >tsaserial
	)
}

start_tsa() {
	local pf=$OUT/pki/tsa.port
	python3 "$HERE/tsa.py" "$OUT/pki/ts.cnf" "$OUT/pki/tsa.pem" "$OUT/pki/tsa.key" "$pf" &
	TSA_PID=$!
	trap 'kill $TSA_PID 2>/dev/null || true' EXIT
	for _ in $(seq 50); do [ -s "$pf" ] && break; sleep 0.1; done
	[ -s "$pf" ] || { log "TSA did not start"; exit 1; }
	TSA_URL="http://127.0.0.1:$(cat "$pf")/"
}

# --- Samples -----------------------------------------------------------------
write_sources() {
	local d=$1
	cat >"$d/hello.c" <<-'EOF'
		#include <stdio.h>
		static int counter;          /* .bss */
		static const char msg[] = "hello from authentielf e2e";
		int main(int argc, char **argv) {
			counter += argc;
			printf("%s (argc=%d)\n", msg, counter);
			return 0;
		}
	EOF
	cat >"$d/bigbss.c" <<-'EOF'
		#include <stdio.h>
		char big[64 << 20];  /* bss far beyond EOF: compact placement (global so it is kept) */
		int main(void) { big[12345] = 1; printf("bigbss %d\n", big[12345]); return 0; }
	EOF
	cat >"$d/lib.c" <<-'EOF'
		int answer(void) { return 42; }
	EOF
	cat >"$d/main.c" <<-'EOF'
		#include <stdio.h>
		int answer(void);
		int main(void) { printf("answer=%d\n", answer()); return 0; }
	EOF
	cat >"$d/hello.go" <<-'EOF'
		package main

		import (
			"fmt"
			"runtime"
		)

		func main() { fmt.Println("hello from authentielf e2e", runtime.GOARCH) }
	EOF
	cat >"$d/cgo.go" <<-'EOF'
		package main

		// #include <stdio.h>
		// static void hello(void) { puts("hello from cgo"); fflush(stdout); }
		import "C"

		func main() { C.hello() }
	EOF
	(cd "$d" && [ -f go.mod ] || go mod init e2e >/dev/null 2>&1)
}

# run_bin target file [args]: run natively or under qemu-user.
run_bin() {
	local target=$1
	shift
	if [ "$target" = native ]; then
		"$@"
	else
		"${QEMU[$target]}" -L "/usr/${TRIPLE[$target]}" "$@"
	fi
}

flip_byte() { # file offset
	python3 - "$1" "$2" <<-'EOF'
		import sys
		path, off = sys.argv[1], int(sys.argv[2])
		with open(path, "r+b") as f:
		    f.seek(off); b = f.read(1); f.seek(off); f.write(bytes([b[0] ^ 0xff]))
	EOF
}

# check target sample dir exe [file...]: sign exe and the extra files, then
# run exe from dir/signed. EXPECT_PLACEMENT (default legacy-compatible) is the
# required placement of exe's new segment.
check() {
	local target=$1 sample=$2 dir=$3 exe=$4
	shift 4
	local files=("$exe" "$@") pki=$OUT/pki s=$dir/signed
	mkdir -p "$s"
	local want got why=""
	if ! want=$(cd "$dir" && run_bin "$target" "./$exe" 2>&1); then
		record FAIL "$target" "$sample" "original does not run: $want"
		return
	fi
	local placement="" growth=0
	for f in "${files[@]}"; do
		local o=$dir/$f t=$s/$f
		cp "$o" "$t"
		"$AELF" sign -cert-file "$pki/signer1-chain.pem" -key-file "$pki/signer1.key" -t "$TSA_URL" -n "$sample" "$t" >/dev/null ||
			{ why="sign failed for $f"; break; }
		"$AELF" sign -append -hash sha384 -cert-file "$pki/signer2.pem" -key-file "$pki/signer2.key" "$t" >/dev/null ||
			{ why="append failed for $f"; break; }
		"$AELF" verify -q -ca "$pki/root.pem" "$t" || { why="verify failed for $f"; break; }
		[ "$("$AELF" digest "$t" | cut -d' ' -f1)" = "$(sha256sum "$o" | cut -d' ' -f1)" ] ||
			{ why="digest != sha256(original) for $f"; break; }
		local wo ws
		wo=$(readelf -aW "$o" 2>&1 >/dev/null | sort -u || true)
		ws=$(readelf -aW "$t" 2>&1 >/dev/null | sort -u || true)
		[ "$ws" = "$wo" ] || { why="new readelf warnings for $f: $(printf '%s' "$ws" | head -1)"; break; }
		local size=$(($(stat -c %s "$t") - $(stat -c %s "$o")))
		growth=$((growth + size))
		[ "$f" = "$exe" ] && placement=$("$AELF" show "$t" | sed -n 's/^Placement: *//p' | cut -d' ' -f1 | tr -d ,)

		# Tampering must be detected.
		cp "$t" "$s/.tamper"
		flip_byte "$s/.tamper" $(($(stat -c %s "$o") / 2))
		! "$AELF" verify -q -ca "$pki/root.pem" "$s/.tamper" || { why="flipped byte not detected in $f"; break; }
		cp "$t" "$s/.tamper"
		printf 'x' >>"$s/.tamper"
		! "$AELF" verify -q -ca "$pki/root.pem" "$s/.tamper" || { why="appended data not detected in $f"; break; }
		rm -f "$s/.tamper"

		# Unsigning restores the original exactly.
		"$AELF" remove -all -o "$s/.orig" "$t" >/dev/null && cmp -s "$s/.orig" "$o" ||
			{ why="remove -all did not restore $f"; break; }
		rm -f "$s/.orig"
	done
	local want_place=${EXPECT_PLACEMENT:-legacy-compatible}
	if [ -z "$why" ] && [ "$placement" != "$want_place" ]; then
		why="placement $placement, want $want_place"
	fi
	if [ -z "$why" ]; then
		if ! got=$(cd "$s" && run_bin "$target" "./$exe" 2>&1); then
			why="signed binary failed: $got"
		elif [ "$got" != "$want" ]; then
			why="output differs: '$got' vs '$want'"
		fi
	fi
	if [ -n "$why" ]; then
		record FAIL "$target" "$sample" "$why"
	else
		record PASS "$target" "$sample" "+${growth}B placement=$placement"
	fi
}

# build target sample dir cmd...: run a build command, recording failures.
build() {
	local target=$1 sample=$2
	shift 2
	local outp
	if ! outp=$("$@" 2>&1); then
		record FAIL "$target" "$sample" "build failed: $(printf '%s' "$outp" | head -3 | tr '\n' ' ')"
		return 1
	fi
}

run_target() {
	local target=$1 cc goarch d=$OUT/$1
	mkdir -p "$d"
	write_sources "$d"
	if [ "$target" = native ]; then
		cc=cc
		goarch=$(go env GOARCH)
	else
		cc=${TRIPLE[$target]}-gcc
		goarch=${GOARCH_OF[$target]}
		command -v "${QEMU[$target]}" >/dev/null || { missing "$target" "${QEMU[$target]}"; return; }
	fi

	if command -v "$cc" >/dev/null; then
		local -A cflags=([c-pie]="-fPIE -pie" [c-nopie]="-fno-pie -no-pie" [c-static]="-static")
		[ "$target" = native ] && cflags[c-staticpie]="-static-pie"
		for k in "${!cflags[@]}"; do
			mkdir -p "$d/$k"
			# shellcheck disable=SC2086
			build "$target" "$k" "$cc" -O2 ${cflags[$k]} -o "$d/$k/prog" "$d/hello.c" &&
				check "$target" "$k" "$d/$k" prog
		done
		mkdir -p "$d/c-shared"
		build "$target" c-shared "$cc" -O2 -shared -fPIC -o "$d/c-shared/libanswer.so" "$d/lib.c" &&
			build "$target" c-shared "$cc" -O2 -o "$d/c-shared/prog" "$d/main.c" \
				-L"$d/c-shared" -lanswer -Wl,-rpath,'$ORIGIN' &&
			check "$target" c-shared "$d/c-shared" prog libanswer.so
		if [ "$target" = native ]; then
			mkdir -p "$d/c-bigbss"
			build "$target" c-bigbss "$cc" -O2 -o "$d/c-bigbss/prog" "$d/bigbss.c" &&
				EXPECT_PLACEMENT=compact check "$target" c-bigbss "$d/c-bigbss" prog
		fi
	else
		missing "$target" "$cc"
	fi

	if command -v go >/dev/null; then
		mkdir -p "$d/go-static"
		build "$target" go-static env -C "$d" CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" GOARM=7 \
			go build -o go-static/prog hello.go && check "$target" go-static "$d/go-static" prog
		if [ "$target" = native ]; then
			mkdir -p "$d/go-cgo" "$d/go-pie"
			build "$target" go-cgo env -C "$d" CGO_ENABLED=1 go build -o go-cgo/prog cgo.go &&
				check "$target" go-cgo "$d/go-cgo" prog
			build "$target" go-pie env -C "$d" CGO_ENABLED=1 go build -buildmode=pie -o go-pie/prog hello.go &&
				check "$target" go-pie "$d/go-pie" prog
		fi
	else
		missing "$target" go
	fi
}

setup_pki
start_tsa
for t in "${targets[@]}"; do
	if [ "$t" != native ] && [ -z "${TRIPLE[$t]:-}" ]; then
		log "unknown target $t (known: ${ALL_TARGETS[*]})"
		exit 2
	fi
	log "== $t"
	run_target "$t"
done
printf '\n%d passed, %d failed, %d skipped (report: %s)\n' "$pass" "$fail" "$skip" "$REPORT" | tee -a "$REPORT"
[ "$fail" -eq 0 ]
