#!/bin/sh
# rwsamplecheck.sh -- `make check` gate for the road-warrior sample pack: every
# samples/roadwarrior/*.conf must pass `iked -C` once its EDIT paths point at
# real (throwaway) credentials: a CA and a CA-issued gateway certificate
# (SAN + serverAuth, verified against the CA) like a real deployment.
# Run from iked/ (IKED defaults to ./iked).
set -u
IKED=${IKED:-./iked}
SRC=${srcdir:-.}/../samples/roadwarrior
T=$(mktemp -d "${TMPDIR:-/tmp}/rwconf.XXXXXX") || exit 99
trap 'rm -rf "$T"' EXIT
command -v openssl >/dev/null 2>&1 || { echo "SKIP: no openssl(1)"; exit 77; }
mkdir -p "$T/psk" "$T/cert"
printf 'rw-sample-psk-0123456789abcdef\n' >"$T/psk/rw.psk"
printf 'spmd-pwd\n' >"$T/spmd.pwd"
printf 'radius-secret\n' >"$T/radius.secret"
chmod 600 "$T/psk/rw.psk" "$T/spmd.pwd" "$T/radius.secret"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=rw-ca \
    -keyout "$T/cert/ca.key" -out "$T/cert/ca.crt" >/dev/null 2>&1 &&
printf 'subjectAltName=DNS:vpn.example.net\nextendedKeyUsage=serverAuth\n' >"$T/cert/gw.ext" &&
openssl req -new -newkey rsa:2048 -nodes -subj /CN=vpn.example.net \
    -keyout "$T/cert/gw.key" -out "$T/cert/gw.csr" >/dev/null 2>&1 &&
openssl x509 -req -in "$T/cert/gw.csr" -CA "$T/cert/ca.crt" -CAkey "$T/cert/ca.key" \
    -CAcreateserial -days 2 -extfile "$T/cert/gw.ext" -out "$T/cert/gw.crt" >/dev/null 2>&1 &&
openssl verify -CAfile "$T/cert/ca.crt" "$T/cert/gw.crt" >/dev/null 2>&1 ||
    { echo "FAIL: cannot make test certificates"; exit 1; }
chmod 600 "$T/cert/"*.key
rc=0
n=0
for f in "$SRC"/*.conf; do
	n=$((n + 1))
	sed "s|/usr/local/racoon2/etc/racoon2|$T|g" "$f" >"$T/test.conf"
	if out=$("$IKED" -C -f "$T/test.conf" 2>&1); then
		echo "PASS: $(basename "$f") passes iked -C"
	else
		echo "FAIL: $(basename "$f"): $out"
		rc=1
	fi
done
[ "$n" -ge 3 ] || { echo "FAIL: only $n sample configs found in $SRC"; rc=1; }
exit $rc
