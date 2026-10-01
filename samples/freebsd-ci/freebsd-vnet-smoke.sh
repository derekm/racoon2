#!/bin/sh
# samples/freebsd-ci/freebsd-vnet-smoke.sh - FreeBSD vnet conformance:
# runs the real iked<->iked ESP tunnel across TWO vnet jails on ONE epair(4)
# (FreeBSD's analogues of Linux netns + veth), driven through the pfkey KM
# (if_pfkeyv2.c - auto-selected on FreeBSD; *linux*->xfrm, *->pfkey).
# This is the FIRST BSD leg that runs an actual tunnel matrix (the NetBSD
# legs are build+rc.d smoke only: "npf/pf/ipf is packet filter, not
# SAD/SPD").
#
# PF_KEY SAD/SPD is kernel-global on stock FreeBSD (not per-vnet), so the
# ESP child shows up in the host `setkey -D`; the two jails give each seat
# its own stack+port-500 (the isolation the Linux matrix gets from netns).
#
# Assumes /usr/local/racoon2 is installed (build script ran first) and
# ipsec-tools setkey is installed (its /usr/local/sbin may not be in PATH).
# Diagnosable on blind CI runs: every seat logs to /tmp/freeb-*; the SADB
# dump is retained.  Exits non-zero on failure.
set -eu
PREFIX="${PREFIX:-/usr/local/racoon2}"
SBIN="${PREFIX}/sbin"
CONF="${SYSCONFDIR:-${PREFIX}/etc/racoon2}"
# /usr/local/sbin (setkey from ipsec-tools) is not in PATH on FreeBSD VM.
export PATH="$PATH:/usr/local/sbin"

jr=r2vr   # responder vnet jail
ji=r2vi   # initiator vnet jail
hr=192.0.5.1
hi=192.0.5.2

for S in "$SBIN/iked" "$SBIN/spmd" "$SBIN/ikedctl"; do
	[ -x "$S" ] || { echo "FAIL: missing $S"; exit 1; }
done
command -v setkey >/dev/null 2>&1 || { echo "FAIL: setkey not found (install ipsec-tools)"; exit 1; }

echo "=== cleanup any previous leg residue (self-healing like the linux kinds) ==="
jexec $jr /bin/sh -c 'killall iked spmd 2>/dev/null' || true
jexec $ji /bin/sh -c 'killall iked spmd 2>/dev/null' || true
jail -r $jr 2>/dev/null || true
jail -r $ji 2>/dev/null || true

echo "=== ONE epair, both ends into the two vnet jails ==="
set +e; ifconfig epair create 2>/dev/null > /tmp/freeb-epair.txt; r=$?; set -e
[ "$r" -eq 0 ] || { echo "FAIL: ifconfig epair create (does GENERIC have VIMAGE/if_epair?)"; cat /tmp/freeb-epair.txt; exit 1; }
e=$(cat /tmp/freeb-epair.txt)
# e is "epair0a epair0b"; a goes to responder jail (hr), b to initiator (hi).
ea=$(echo "$e" | awk '{print $1}')
eb=$(echo "$e" | awk '{print $2}')
echo "epair ends: $ea (resp) / $eb (init)"
jail -c name=$jr persist vnet vnet.interface="$ea" || { echo "FAIL: jail -c $jr"; exit 1; }
jail -c name=$ji persist vnet vnet.interface="$eb" || { echo "FAIL: jail -c $ji"; exit 1; }
jexec $jr ifconfig "$ea" inet "$hr/24" up || { echo "FAIL: $jr addr"; exit 1; }
jexec $ji ifconfig "$eb" inet "$hi/24" up || { echo "FAIL: $ji addr"; exit 1; }
jexec $jr ifconfig lo0 inet 127.0.0.1/8 up 2>/dev/null || true
jexec $ji ifconfig lo0 inet 127.0.0.1/8 up 2>/dev/null || true
echo "=== ping across the cable (both stacks up) ==="
jexec $ji ping -c 1 -t 2 $hr > /tmp/freeb-ping.txt 2>&1 || echo "note: icmp across epair failed (not a gate; IKE needs only the route)"
grep -qE '1 received|bytes from' /tmp/freeb-ping.txt && echo "cable OK: $ji sees $hr" || echo "note: ping inconclusive (see /tmp/freeb-ping.txt)"

echo "=== throwaway CI PSK (random raw bytes, never the box PSK) + per-seat configs ==="
install -d -m 0755 /tmp/freeb
# rcf_readfile() reads pre_shared_key files as RAW BYTES (ike_conf.c:939),
# so write 32 raw bytes (the box matrix PSK shape), no trailing newline.
dd if=/dev/urandom of=/tmp/freeb/test.psk bs=32 count=1 2>/dev/null
chmod 600 /tmp/freeb/test.psk
cat > /tmp/freeb/responder.conf <<EOF
interface {
	ike { $hr; };
	spmd { unix "/tmp/freeb/resp-spmif"; };
	spmd_password "/tmp/freeb/spmd.pwd";
};
resolver { resolver off; };
remote matrix_resp {
	acceptable_kmp { ikev2; };
	ikev2 {
		passive on;
		my_id fqdn "racoon2-matrix";
		peers_id fqdn "r2init-matrix";
		peers_ipaddr $hi;
		kmp_enc_alg { aes128_cbc; };
		kmp_prf_alg { hmac_sha2_256; };
		kmp_hash_alg { hmac_sha2_256; };
		kmp_dh_group { modp2048; };
		kmp_auth_method { psk; };
		pre_shared_key "/tmp/freeb/test.psk";
		dpd_delay 60 sec;
	};
	selector_index sel_in;
};
selector sel_out {
	direction outbound;
	src $hr; dst $hi;
	policy_index pol;
};
selector sel_in {
	direction inbound;
	dst $hr; src $hi;
	policy_index pol;
};
policy pol {
	action auto_ipsec;
	remote_index matrix_resp;
	ipsec_mode tunnel;
	ipsec_index { ipsec_e; };
	ipsec_level require;
	peers_sa_ipaddr $hi;
	my_sa_ipaddr $hr;
};
ipsec ipsec_e {
	ipsec_sa_lifetime_time 300 sec;
	sa_index esp_e;
};
sa esp_e {
	sa_protocol esp;
	esp_enc_alg { aes128_cbc; };
	esp_auth_alg { hmac_sha2_256; };
};
EOF
cat > /tmp/freeb/initiator.conf <<EOF
interface {
	ike { $hi; };
	spmd { unix "/tmp/freeb/init-spmif"; };
	spmd_password "/tmp/freeb/spmd.pwd";
};
resolver { resolver off; };
remote matrix_init {
	acceptable_kmp { ikev2; };
	ikev2 {
		passive off;
		my_id fqdn "r2init-matrix";
		peers_id fqdn "racoon2-matrix";
		peers_ipaddr $hr;
		kmp_enc_alg { aes128_cbc; };
		kmp_prf_alg { hmac_sha2_256; };
		kmp_hash_alg { hmac_sha2_256; };
		kmp_dh_group { modp2048; };
		kmp_auth_method { psk; };
		pre_shared_key "/tmp/freeb/test.psk";
		dpd_delay 60 sec;
	};
	selector_index sel_in;
};
selector sel_out {
	direction outbound;
	src $hi; dst $hr;
	policy_index pol;
};
selector sel_in {
	direction inbound;
	dst $hi; src $hr;
	policy_index pol;
};
policy pol {
	action auto_ipsec;
	remote_index matrix_init;
	ipsec_mode tunnel;
	ipsec_index { ipsec_e; };
	ipsec_level require;
	peers_sa_ipaddr $hr;
	my_sa_ipaddr $hi;
};
ipsec ipsec_e {
	ipsec_sa_lifetime_time 300 sec;
	sa_index esp_e;
};
sa esp_e {
	sa_protocol esp;
	esp_enc_alg { aes128_cbc; };
	esp_auth_alg { hmac_sha2_256; };
};
EOF
printf 'ci-spmd-pw\n' > /tmp/freeb/spmd.pwd
chmod 600 /tmp/freeb/spmd.pwd

echo "=== start spmd + iked per seat (inside their vnet jails) ==="
# RACOON2_ADMIN_SOCK is per-seat (jails share the host fs; a shared default
# admin-socket path would collide).  ikedctl talks to THIS socket, not the
# spmif (the Linux kinds use the same pattern).
jexec $jr /bin/sh -c "env RACOON2_ADMIN_SOCK=/tmp/freeb/resp-ctl RACOON2_RESUME_DIR=/tmp/freeb/resp-resume $SBIN/spmd -F -f /tmp/freeb/responder.conf > /tmp/freeb/resp-spmd.log 2>&1 &" || true
jexec $ji /bin/sh -c "env RACOON2_ADMIN_SOCK=/tmp/freeb/init-ctl RACOON2_RESUME_DIR=/tmp/freeb/init-resume $SBIN/spmd -F -f /tmp/freeb/initiator.conf > /tmp/freeb/init-spmd.log 2>&1 &" || true
sleep 2
jexec $jr /bin/sh -c "env RACOON2_ADMIN_SOCK=/tmp/freeb/resp-ctl RACOON2_RESUME_DIR=/tmp/freeb/resp-resume $SBIN/iked -F -f /tmp/freeb/responder.conf -D 0x0001 -l /tmp/freeb/resp-iked.log > /tmp/freeb/resp-iked.out 2>&1 &" || true
jexec $ji /bin/sh -c "env RACOON2_ADMIN_SOCK=/tmp/freeb/init-ctl RACOON2_RESUME_DIR=/tmp/freeb/init-resume $SBIN/iked -F -f /tmp/freeb/initiator.conf -D 0x0001 -l /tmp/freeb/init-iked.log > /tmp/freeb/init-iked.out 2>&1 &" || true
sleep 3

echo "=== establish IKE/ESP from the initiator seat ==="
jexec $ji $SBIN/ikedctl -s /tmp/freeb/init-ctl establish-sa isakmp inet $hi $hr sel_out > /tmp/freeb/ctl.out 2>&1 || true

up=0
i=0
while [ "$i" -lt 45 ]; do
	# kernel-global PF_KEY SADB: count ESP tunnel SAs (one per direction).
	n=$(setkey -D 2>/dev/null | grep -cE 'esp mode=tunnel' || true)
	if [ "$n" -ge 2 ]; then
		up=1
		break
	fi
	i=$((i+1)); sleep 1
done

echo "=== SADB dump (retained for diagnosis) ==="
setkey -D > /tmp/freeb/sadb-dump.txt 2>&1 || true
setkey -DP > /tmp/freeb/spd-dump.txt 2>&1 || true
echo "ESP tunnel SAs in kernel SADB: $(setkey -D 2>/dev/null | grep -cE 'esp mode=tunnel' || true)"
sed -n '1,50p' /tmp/freeb/sadb-dump.txt 2>/dev/null || true

echo "=== iked logs (tail) ==="
echo "--- responder iked ---"; tail -25 /tmp/freeb/resp-iked.log 2>/dev/null || true
echo "--- initiator iked ---"; tail -25 /tmp/freeb/init-iked.log 2>/dev/null || true

echo "=== verdict ==="
if [ "$up" -eq 1 ]; then
	lines=$(setkey -D 2>/dev/null | grep -cE 'esp mode=tunnel' || true)
	echo "PASS freebsd-vnet i2iinit-esp (pfkey KM: $lines ESP tunnel SAs on $hr<->$hi in kernel SADB)"
	echo "CPL B1: PASS freebsd pfkey KM ESP child up (AES-CBC-128, setkey -D evidence)"
	# leave the dumps as artifacts, but stop the daemons and drop the jails
	jexec $jr /bin/sh -c 'killall iked spmd 2>/dev/null' || true
	jexec $ji /bin/sh -c 'killall iked spmd 2>/dev/null' || true
	jail -r $jr 2>/dev/null || true
	jail -r $ji 2>/dev/null || true
	echo FREEBSD-VNET-OK
	exit 0
fi
echo "FAIL freebsd-vnet i2iinit-esp: no ESP tunnel SAs in kernel SADB after 45s"
echo "--- initiator ikedctl output ---"; cat /tmp/freeb/ctl.out 2>/dev/null || true
echo "--- spmd logs ---"; cat /tmp/freeb/resp-spmd.log /tmp/freeb/init-spmd.log 2>/dev/null || true
echo "--- spd dump ---"; sed -n '1,40p' /tmp/freeb/spd-dump.txt 2>/dev/null || true
exit 1
