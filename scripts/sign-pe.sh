#!/usr/bin/env bash
# Authenticode-sign Windows PE files with jsign (https://ebourg.github.io/jsign/),
# taking the key and certificates from the same variables as
# "authentielf sign", so one configuration signs both ELF and PE:
#
#   SIGN_KEY_FILE   private key PEM file, or gcp-kms://projects/P/locations/L/
#                   keyRings/R/cryptoKeys/K[/cryptoKeyVersions/N]
#                   (token in $GOOGLE_OAUTH_ACCESS_TOKEN)
#   SIGN_KEY        private key PEM text
#   SIGN_CERT_FILE / SIGN_CERT    signer certificate, then intermediates
#   SIGN_CHAIN_FILE / SIGN_CHAIN  extra intermediates (optional)
#   SIGN_TSA        RFC 3161 timestamp server URL (optional)
#   SIGN_NAME       program name (optional)
#   JSIGN           jsign command (default "jsign"; e.g. "java -jar jsign.jar")
#
# For a Cloud KMS crypto key without a version, jsign uses the most recent
# version (authentielf picks the one matching the certificate); name the
# version explicitly if several are enabled.
#
# Usage: scripts/sign-pe.sh <file.exe>...
set -euo pipefail

[ $# -gt 0 ] || { echo "usage: sign-pe.sh <file.exe>..." >&2; exit 2; }
read -ra jsign <<<"${JSIGN:-jsign}"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
chmod 700 "$tmp"

# one_of VAR_FILE VAR NAME prints the path named by $VAR_FILE, or writes
# $VAR's text to $tmp/NAME and prints that path; nothing if neither is set.
one_of() {
	local f=${!1:-} t=${!2:-}
	if [ -n "$f" ] && [ -n "$t" ]; then
		echo "sign-pe.sh: both \$$1 and \$$2 are set; use one" >&2
		return 2
	fi
	if [ -n "$t" ]; then
		(umask 077 && printf '%s\n' "$t" >"$tmp/$3")
		echo "$tmp/$3"
	else
		echo "$f"
	fi
}
key=$(one_of SIGN_KEY_FILE SIGN_KEY key.pem)
cert=$(one_of SIGN_CERT_FILE SIGN_CERT cert.pem)
chain=$(one_of SIGN_CHAIN_FILE SIGN_CHAIN chain.pem)
[ -n "$key" ] || { echo "sign-pe.sh: \$SIGN_KEY_FILE or \$SIGN_KEY is required" >&2; exit 2; }
[ -n "$cert" ] || { echo "sign-pe.sh: \$SIGN_CERT_FILE or \$SIGN_CERT is required" >&2; exit 2; }

# jsign takes one certificate file: signer first, then intermediates.
cat "$cert" ${chain:+"$chain"} >"$tmp/full-chain.pem"

# --replace keeps a retry idempotent (no nested duplicate signature).
args=(--certfile "$tmp/full-chain.pem" --replace)
case $key in
gcp-kms://*)
	res=${key#gcp-kms://}
	re='^(projects/[^/]+/locations/[^/]+/keyRings/[^/]+)/cryptoKeys/([^/]+(/cryptoKeyVersions/[^/]+)?)$'
	[[ $res =~ $re ]] || { echo "sign-pe.sh: malformed key URI $key" >&2; exit 2; }
	[ -n "${GOOGLE_OAUTH_ACCESS_TOKEN:-}" ] ||
		{ echo "sign-pe.sh: set GOOGLE_OAUTH_ACCESS_TOKEN for $key" >&2; exit 2; }
	export GOOGLE_OAUTH_ACCESS_TOKEN
	# env: keeps the token off the command line (and out of ps).
	args+=(--storetype GOOGLECLOUD --keystore "${BASH_REMATCH[1]}"
		--alias "${BASH_REMATCH[2]}" --storepass env:GOOGLE_OAUTH_ACCESS_TOKEN)
	;;
*://*)
	echo "sign-pe.sh: unsupported key URI $key" >&2
	exit 2
	;;
*)
	args+=(--keyfile "$key")
	;;
esac
if [ -n "${SIGN_TSA:-}" ]; then args+=(--tsaurl "$SIGN_TSA" --tsmode RFC3161); fi
if [ -n "${SIGN_NAME:-}" ]; then args+=(--name "$SIGN_NAME"); fi

"${jsign[@]}" "${args[@]}" "$@"
