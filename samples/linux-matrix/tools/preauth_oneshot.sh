#!/bin/sh
# preauth_oneshot.sh <build-dir>
#
# One-datagram pre-auth negative tests against an iked built in <build-dir>
# (meant for an ASan+UBSan build; run as root, it binds 127.0.0.1:500/4500
# and spmd needs the kernel IPsec interface).  Each case sends one crafted
# unauthenticated UDP datagram and requires all of:
#   - iked still running afterwards,
#   - no sanitizer report (ASAN_OPTIONS log_path files stay absent),
#   - the guard's PROTO_ERR line in the iked log.
# Cases:
#   F1  IKE_SA_INIT carrying only N(NAT_DETECTION_SOURCE_IP) with no data
#       (natt_process_natd read 20 bytes past the packet before 7af5626)
#   F2  28-byte ISAKMP header announcing a fragment payload (np 132) with
#       no fragment header (isakmp_handler read past it before 04827fa)
set -u
B=${1:?usage: preauth_oneshot.sh <build-dir>}
B=$(cd "$B" && pwd)
TOP=$(mktemp -d /tmp/r2-oneshot.XXXXXX)
W=$TOP
fail=0

cleanup() {
	[ -n "${IKED_PID:-}" ] && kill "$IKED_PID" 2>/dev/null
	[ -n "${SPMD_PID:-}" ] && kill "$SPMD_PID" 2>/dev/null
	sleep 1
	[ -n "${IKED_PID:-}" ] && kill -9 "$IKED_PID" 2>/dev/null
	[ -n "${SPMD_PID:-}" ] && kill -9 "$SPMD_PID" 2>/dev/null
}
trap cleanup EXIT

# start_case <case>: fresh run dir, conf and daemons for one case, so a
# case that kills iked cannot hide the next one
start_case() {
	W=$TOP/$1
	mkdir -p "$W"
	printf 'oneshot-spmd-password' > "$W/spmd.pwd"
	printf 'oneshot-psk-not-secret' > "$W/test.psk"
	chmod 600 "$W/spmd.pwd" "$W/test.psk"
	cat > "$W/racoon2.conf" <<-CONF
	interface {
		ike { "127.0.0.1"; };
		spmd { unix "$W/spmif"; };
		spmd_password "$W/spmd.pwd";
	};
	resolver { resolver off; };
	remote r1 {
		acceptable_kmp { ikev2; };
		ikev2 {
			passive on;
			my_id fqdn "resp.test";
			peers_id fqdn "init.test";
			peers_ipaddr "127.0.0.1";
			kmp_enc_alg { aes128_cbc; };
			kmp_prf_alg { hmac_sha2_256; };
			kmp_hash_alg { hmac_sha2_256; };
			kmp_dh_group { modp2048; };
			kmp_auth_method { psk; };
			pre_shared_key "$W/test.psk";
		};
		selector_index sel_in;
	};
	selector sel_out { direction outbound; src "127.0.0.1"; dst "127.0.0.1"; policy_index pol; };
	selector sel_in { direction inbound; dst "127.0.0.1"; src "127.0.0.1"; policy_index pol; };
	policy pol { action auto_ipsec; remote_index r1; ipsec_mode transport; ipsec_index { ipsec_e; }; ipsec_level require; };
	ipsec ipsec_e { ipsec_sa_lifetime_time 60 sec; sa_index esp_e; };
	sa esp_e { sa_protocol esp; esp_enc_alg { aes128_cbc; }; esp_auth_alg { hmac_sha2_256; }; };
	CONF

	export ASAN_OPTIONS="log_path=$W/asan:detect_leaks=0:abort_on_error=0"
	export UBSAN_OPTIONS="log_path=$W/ubsan:print_stacktrace=1"
	export RACOON2_ADMIN_SOCK="$W/admin.sock"
	export RACOON2_RESUME_DIR="$W/resume"
	mkdir -p "$W/resume"

	"$B/spmd/spmd" -F -f "$W/racoon2.conf" > "$W/spmd.log" 2>&1 &
	SPMD_PID=$!
	i=0; until [ -S "$W/spmif" ] || [ "$i" -ge 20 ]; do sleep 1; i=$((i+1)); done
	"$B/iked/iked" -F -f "$W/racoon2.conf" -D 0x0001 -l "$W/iked.log" > "$W/iked.out" 2>&1 &
	IKED_PID=$!
	i=0; until grep -q 'bind 127.0.0.1\[500\]' "$W/iked.log" 2>/dev/null || [ "$i" -ge 20 ]; do sleep 1; i=$((i+1)); done
	if ! kill -0 "$IKED_PID" 2>/dev/null || ! grep -q 'bind 127.0.0.1\[500\]' "$W/iked.log" 2>/dev/null; then
		echo "ONESHOT: FAIL iked did not come up"
		tail -20 "$W/iked.log" "$W/iked.out" "$W/spmd.log" 2>/dev/null
		return 1
	fi
	return 0
}

stop_case() {
	cleanup
	IKED_PID=; SPMD_PID=
}

send() {
	python3 - "$1" <<'PY'
import os, socket, struct, sys
case = sys.argv[1]
if case == "F1":
    notify = struct.pack('!BBH', 0, 0, 8) + struct.pack('!BBH', 0, 0, 16388)
    hdr = os.urandom(8) + b'\0' * 8 + struct.pack('!BBBBII', 41, 0x20, 34, 0x08, 0, 28 + len(notify))
    pkt = hdr + notify
elif case == "F2":
    pkt = os.urandom(8) + os.urandom(8) + struct.pack('!BBBBII', 132, 0x10, 5, 0, 0x11223344, 28)
else:
    sys.exit(2)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('127.0.0.1', 0))
s.sendto(pkt, ('127.0.0.1', 500))
PY
}

# true if ASan/UBSan wrote any report (log_path files are <prefix>.<pid>)
sanitizer_reports() {
	for f in "$W"/asan.* "$W"/ubsan.*; do
		[ -e "$f" ] && return 0
	done
	return 1
}

check() {	# check <case> <guard-regex>
	start_case "$1" || { fail=1; stop_case; return; }
	send "$1" || { echo "ONESHOT: FAIL $1 sender"; fail=1; stop_case; return; }
	i=0; until grep -qE "$2" "$W/iked.log" 2>/dev/null || [ "$i" -ge 10 ]; do sleep 1; i=$((i+1)); done
	sleep 1
	ok=1
	kill -0 "$IKED_PID" 2>/dev/null || { echo "ONESHOT: FAIL $1 iked died"; ok=0; }
	if sanitizer_reports; then
		echo "ONESHOT: FAIL $1 sanitizer report:"
		for f in "$W"/asan.* "$W"/ubsan.*; do
			[ -e "$f" ] && head -40 "$f"
		done
		ok=0
	fi
	grep -qE "$2" "$W/iked.log" 2>/dev/null || { echo "ONESHOT: FAIL $1 guard line '$2' not logged"; ok=0; }
	if [ "$ok" = 1 ]; then
		echo "ONESHOT: PASS $1 ($(grep -oE "$2" "$W/iked.log" | head -1))"
	else
		fail=1
		grep -E 'PROTO_ERR|bytes message received' "$W/iked.log" | tail -6
	fi
	stop_case
}

check F1 'NAT_DETECTION notify data length 0 != 20'
check F2 'IKE fragment too short \(28\)'

if [ "$fail" = 0 ]; then echo "ONESHOT: all cases passed"; else echo "ONESHOT: FAILURES"; fi
exit "$fail"
