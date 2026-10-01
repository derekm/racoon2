#!/bin/sh
# samples/freebsd-ci/freebsd-vnet-smoke.sh - FreeBSD vnet conformance:
# runs real iked<->iked tunnels across TWO vnet jails on ONE epair(4) per row
# (FreeBSD's analogues of Linux netns + veth), driven through the pfkey KM
# (if_pfkeyv2.c - auto-selected on FreeBSD; *linux*->xfrm, *->pfkey).
# This is the FIRST BSD leg that runs an actual tunnel matrix (the NetBSD
# legs are build+rc.d smoke only: "npf/pf/ipf is packet filter, not
# SAD/SPD").  Rows mirror linux-matrix kinds so pfkey parity can be
# asserted against xfrm on the same config:
#   i2iinit-esp : initial IKE_SA + ESP child  (mirrors linux i2iinit)
#   i2ike-rekey : CREATE_CHILD child-SA rekey, new SPI BOTH seats, after
#                 the initiator's short ipsec lifetime fires
#                 (mirrors linux i2ike rows' SPI gate; pfkey SADB UPDATE)
#   i2iv6-esp   : same tunnel over AF_INET6 (mirrors linux i2iv6)
#   (i2iv6-esp is defined but SKIPPED unless ROW=i2iv6-esp: it waits on a
#   veth/ND head-swap that is a no-op on epair, staged separately.)
#
# PF_KEY SAD/SPD on stock FreeBSD is VIMAGE-virtualized PER-VNET JAIL
# (sys/netipsec/key.c): the ESP child is only visible from INSIDE each jail
# (the host `setkey -D` is the host vnet and stays empty).  The two jails
# give each seat its own stack+port-500, matching the isolation the Linux
# matrix gets from netns.
#
# Assumes /usr/local/racoon2 is installed (build script ran first) and
# ipsec-tools setkey is installed (its /usr/local/sbin may not be in PATH).
# Diagnosable on blind CI runs: every seat logs to /tmp/freeb-*; the SADB
# dumps are retained.  All rows must pass; exits non-zero on any failure.
set -eu
PREFIX="${PREFIX:-/usr/local/racoon2}"
SBIN="${PREFIX}/sbin"
CONF="${SYSCONFDIR:-${PREFIX}/etc/racoon2}"
# /usr/local/sbin (setkey from ipsec-tools) is not in PATH on FreeBSD VM.
export PATH="$PATH:/usr/local/sbin"
ROW="${ROW:-i2iinit-esp}"

jr=r2vr   # responder vnet jail
ji=r2vi   # initiator vnet jail
SEP="======================================================"

for S in "$SBIN/iked" "$SBIN/spmd" "$SBIN/ikedctl"; do
	[ -x "$S" ] || { echo "FAIL: missing $S"; exit 1; }
done
command -v setkey >/dev/null 2>&1 || { echo "FAIL: setkey not found (install ipsec-tools)"; exit 1; }

spi() { # spi $JAIL : sorted SPI set in that jail's per-vnet SADB
	jexec "$1" /usr/local/sbin/setkey -D 2>/dev/null | grep -oE 'spi=[0-9]+' | sort -u
}
esp_up() { # esp_up $JAIL : count of esp tunnel SAs in that jail's SADB
	jexec "$1" /usr/local/sbin/setkey -D 2>/dev/null | grep -cE 'esp mode=tunnel' || true
}

jails_teardown() {
jexec $jr /bin/sh -c 'killall iked spmd 2>/dev/null' || true
jexec $ji /bin/sh -c 'killall iked spmd 2>/dev/null' || true
jail -r $jr 2>/dev/null || true
jail -r $ji 2>/dev/null || true
# stale admin/spmif sockets would block the NEXT row's daemons from binding
rm -f /tmp/freeb/*-ctl* /tmp/freeb/*-spmif*
rm -f /tmp/freeb-epair.txt
}

# run_row <name> <family> <hr> <hi> <enc> <auth> <lft_init_sec> <lft_resp_sec> <rekey:0/1>
run_row() {
	_name=$1 _fam=$2 _hr=$3 _hi=$4 _enc=$5 _auth=$6 _lfti=$7 _lftr=$8 _rekey=$9
	echo "$SEP"
	echo "=== ROW $_name (family=$_fam) ==="
	hr=$_hr; hi=$_hi
	[ "$_fam" = inet6 ] && spmif_sfx=v6 || spmif_sfx=""
	jails_teardown

	echo "=== cleanup + ONE epair, both ends into the two vnet jails ==="
	set +e; ifconfig epair create 2>/dev/null > /tmp/freeb-epair.txt; r=$?; set -e
	[ "$r" -eq 0 ] || { echo "FAIL: ifconfig epair create (does GENERIC have VIMAGE/if_epair?)"; cat /tmp/freeb-epair.txt; exit 1; }
	# `ifconfig epair create` prints the PRIMARY end's name only (e.g. epair0a);
	# the peer is its sibling: epair pairs are always <name>a / <name>b.
	ea=$(head -1 /tmp/freeb-epair.txt | awk '{print $1}' | tr -d ':')
	case "$ea" in
		*a) eb="${ea%a}b" ;;
		*b) eb="${ea%b}a" ;;
		*) echo "FAIL: unexpected epair name '$ea'"; exit 1 ;;
	esac
	echo "epair ends: $ea (resp) / $eb (init)"
	jail -c name=$jr persist vnet vnet.interface="$ea" || { echo "FAIL: jail -c $jr (vnet.interface=$ea)"; exit 1; }
	jail -c name=$ji persist vnet vnet.interface="$eb" || { echo "FAIL: jail -c $ji (vnet.interface=$eb)"; exit 1; }
	jexec $jr ifconfig "$ea" inet "$hr/24" up || { echo "FAIL: $jr addr"; exit 1; }
	jexec $ji ifconfig "$eb" inet "$hi/24" up || { echo "FAIL: $ji addr"; exit 1; }
	jexec $jr ifconfig lo0 inet 127.0.0.1/8 up 2>/dev/null || true
	jexec $ji ifconfig lo0 inet 127.0.0.1/8 up 2>/dev/null || true
	echo "=== ping across the cable (both stacks up) ==="
	jexec $ji ping -c 1 -t 2 $hr > /tmp/freeb-ping.txt 2>&1 || true
	grep -qE '1 received|bytes from' /tmp/freeb-ping.txt && echo "cable OK: $ji sees $hr" || echo "note: ping inconclusive"

	echo "=== throwaway CI PSK (random raw bytes, never the box PSK) + per-seat configs ==="
	install -d -m 0755 /tmp/freeb
	# rcf_readfile() reads pre_shared_key files as RAW BYTES (ike_conf.c:939),
	# so write 32 raw bytes (the box matrix PSK shape), no trailing newline.
	dd if=/dev/urandom of=/tmp/freeb/test.psk bs=32 count=1 2>/dev/null
	chmod 600 /tmp/freeb/test.psk
	cat > /tmp/freeb/responder.conf <<EOF
interface {
	ike { $hr; };
	spmd { unix "/tmp/freeb/resp-spmif$spmif_sfx"; };
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
	ipsec_sa_lifetime_time $_lfti sec;
	sa_index esp_e;
};
sa esp_e {
	sa_protocol esp;
	esp_enc_alg { $_enc; };
	esp_auth_alg { $_auth; };
};
EOF
	cat > /tmp/freeb/initiator.conf <<EOF
interface {
	ike { $hi; };
	spmd { unix "/tmp/freeb/init-spmif$spmif_sfx"; };
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
	ipsec_sa_lifetime_time $_lftr sec;
	sa_index esp_e;
};
sa esp_e {
	sa_protocol esp;
	esp_enc_alg { $_enc; };
	esp_auth_alg { $_auth; };
};
EOF
	printf 'ci-spmd-pw\n' > /tmp/freeb/spmd.pwd
	chmod 600 /tmp/freeb/spmd.pwd

	echo "=== start spmd + iked per seat (inside their vnet jails) ==="
	# RACOON2_ADMIN_SOCK is per-seat (jails share the host fs; a shared default
	# admin-socket path would collide).  ikedctl talks to THIS socket, not the
	# spmif (the Linux kinds use the same pattern).
	jexec $jr /bin/sh -c "env RACOON2_ADMIN_SOCK=/tmp/freeb/resp-ctl$spmif_sfx RACOON2_RESUME_DIR=/tmp/freeb/resp-resume $SBIN/spmd -F -f /tmp/freeb/responder.conf > /tmp/freeb/resp-spmd.log 2>&1 &" || true
	jexec $ji /bin/sh -c "env RACOON2_ADMIN_SOCK=/tmp/freeb/init-ctl$spmif_sfx RACOON2_RESUME_DIR=/tmp/freeb/init-resume $SBIN/spmd -F -f /tmp/freeb/initiator.conf > /tmp/freeb/init-spmd.log 2>&1 &" || true
	# Wait for BOTH spmif sockets before starting iked (iked connects to spmd at
	# startup; the Linux kinds gate the same way with `until [ -S $SPMIF ]`).
	i=0
	while [ "$i" -lt 15 ]; do
		if [ -S "/tmp/freeb/resp-spmif$spmif_sfx" ] && [ -S "/tmp/freeb/init-spmif$spmif_sfx" ]; then
			break
		fi
		i=$((i+1)); sleep 1
	done
	[ -S "/tmp/freeb/resp-spmif$spmif_sfx" ] && [ -S "/tmp/freeb/init-spmif$spmif_sfx" ] || echo "note: spmif sockets slow (resp=$([ -S "/tmp/freeb/resp-spmif$spmif_sfx" ] && echo yes || echo no) init=$([ -S "/tmp/freeb/init-spmif$spmif_sfx" ] && echo yes || echo no))"
	sleep 1
	jexec $jr /bin/sh -c "env RACOON2_ADMIN_SOCK=/tmp/freeb/resp-ctl$spmif_sfx RACOON2_RESUME_DIR=/tmp/freeb/resp-resume $SBIN/iked -F -f /tmp/freeb/responder.conf -D 0x0001 -l /tmp/freeb/resp-iked.log > /tmp/freeb/resp-iked.out 2>&1 &" || true
	jexec $ji /bin/sh -c "env RACOON2_ADMIN_SOCK=/tmp/freeb/init-ctl$spmif_sfx RACOON2_RESUME_DIR=/tmp/freeb/init-resume $SBIN/iked -F -f /tmp/freeb/initiator.conf -D 0x0001 -l /tmp/freeb/init-iked.log > /tmp/freeb/init-iked.out 2>&1 &" || true
	sleep 3

	echo "=== establish IKE/ESP from the initiator seat (establish-sa inet$_fam selector) ==="
	jexec $ji $SBIN/ikedctl -s "/tmp/freeb/init-ctl$spmif_sfx" establish-sa isakmp $_fam $hi $hr sel_out > /tmp/freeb/ctl.out 2>&1 || true

	up=0
	i=0
	while [ "$i" -lt 45 ]; do
		# SADB is PER-VNET on FreeBSD: count each seat's own kernel SADB.
		rn=$(esp_up $jr)
		in=$(esp_up $ji)
		if [ "$rn" -ge 1 ] && [ "$in" -ge 1 ]; then
			up=1
			break
		fi
		i=$((i+1)); sleep 1
	done

	if [ "$up" -eq 1 ] && [ "$_rekey" -eq 1 ]; then
		# CREATE_CHILD child-SA rekey: a short initiator ipsec lifetime fires
		# the soft boundary, a NEW ESP SPI replaces the initial child on BOTH
		# seats (mirrors the linux i2ike SPI gate, but over pfkey SADB UPDATE).
		echo "=== row $_name: child UP; now assert CREATE_CHILD rekey (new ESP SPI both seats) ==="
		R0=$(spi $jr); I0=$(spi $ji)
		echo "initial SPIs R=[$(echo $R0 | tr '\n' ' ')] I=[$(echo $I0 | tr '\n' ' ')]"
		printf '%s\n' "$R0" > /tmp/freeb/R0.txt
		printf '%s\n' "$I0" > /tmp/freeb/I0.txt
		rekeyed=0
		i=0
		while [ "$i" -lt 90 ]; do
			spi $jr > /tmp/freeb/Rn.txt
			spi $ji > /tmp/freeb/In.txt
			# new SPI on each seat = an SPI present now that was absent at init
			nr=$(comm -13 /tmp/freeb/R0.txt /tmp/freeb/Rn.txt | grep -c spi || true)
			ni=$(comm -13 /tmp/freeb/I0.txt /tmp/freeb/In.txt | grep -c spi || true)
			if [ "$nr" -ge 1 ] && [ "$ni" -ge 1 ]; then
				echo "row $_name: CREATE_CHILD rekey new SPI both seats at ${i}s (R:[$(tr '\n' ' ' < /tmp/freeb/Rn.txt)] I:[$(tr '\n' ' ' < /tmp/freeb/In.txt)])"
				rekeyed=1
				break
			fi
			i=$((i+1)); sleep 1
		done
		[ "$rekeyed" -eq 1 ] || { echo "FAIL row $_name: no new ESP SPI in 90s; R now: $(spi $jr | tr '\n' ' '), I now: $(spi $ji | tr '\n' ' ')"; up=0; }
	fi

	echo "=== SAD/SPD dump from INSIDE each vnet jail (retained for diagnosis) ==="
	jexec $jr /usr/local/sbin/setkey -D > /tmp/freeb/resp-sadb.txt 2>&1 || true
	jexec $ji /usr/local/sbin/setkey -D > /tmp/freeb/init-sadb.txt 2>&1 || true
	jexec $jr /usr/local/sbin/setkey -DP > /tmp/freeb/resp-spd.txt 2>&1 || true
	jexec $ji /usr/local/sbin/setkey -DP > /tmp/freeb/init-spd.txt 2>&1 || true
	echo "responder jail ESP tunnel SAs: $(grep -cE 'esp mode=tunnel' /tmp/freeb/resp-sadb.txt 2>/dev/null || echo 0)"
	echo "initiator jail ESP tunnel SAs: $(grep -cE 'esp mode=tunnel' /tmp/freeb/init-sadb.txt 2>/dev/null || echo 0)"
	echo "--- responder jail SADB ---"; sed -n '1,50p' /tmp/freeb/resp-sadb.txt 2>/dev/null || true
	echo "--- initiator jail SADB ---"; sed -n '1,50p' /tmp/freeb/init-sadb.txt 2>/dev/null || true
	echo "--- responder jail SPD ---"; sed -n '1,30p' /tmp/freeb/resp-spd.txt 2>/dev/null || true
	echo "--- initiator jail SPD ---"; sed -n '1,30p' /tmp/freeb/init-spd.txt 2>/dev/null || true

	echo "=== iked logs (tail) ==="
	echo "--- responder iked ---"; tail -25 /tmp/freeb/resp-iked.log 2>/dev/null || true
	echo "--- initiator iked ---"; tail -25 /tmp/freeb/init-iked.log 2>/dev/null || true

	echo "=== verdict (row $_name) ==="
	if [ "$up" -eq 1 ]; then
		lines=$(grep -cE 'esp mode=tunnel' /tmp/freeb/resp-sadb.txt /tmp/freeb/init-sadb.txt 2>/dev/null | awk -F: '{s+=$2} END{print s}')
		echo "PASS freebsd-vnet $_name (pfkey KM: $lines ESP tunnel SAs on $hr<->$hi in the per-vnet SADBs)"
		echo "CPL B1: PASS freebsd pfkey KM ESP child up ($_enc, per-jail setkey -D evidence)"
		jails_teardown
		return 0
	fi
	echo "FAIL freebsd-vnet $_name: no ESP tunnel SAs in either per-vnet SADB after timeout"
	echo "--- initiator ikedctl output ---"; cat /tmp/freeb/ctl.out 2>/dev/null || true
	echo "--- spmd logs ---"; cat /tmp/freeb/resp-spmd.log /tmp/freeb/init-spmd.log 2>/dev/null || true
	echo "$SEP"
	return 1
}

fail=0
case "$ROW" in
	i2iinit-esp) run_row i2iinit-esp inet 192.0.5.1 192.0.5.2 aes128_cbc hmac_sha2_256 300 3600 0 || fail=1 ;;
	i2ike-rekey) run_row i2ike-rekey inet 192.0.5.1 192.0.5.2 aes128_cbc hmac_sha2_256 60 3600 1 || fail=1 ;;
	i2iv6-esp)   echo "ROW i2iv6-esp staged (ND head-swap no-op on epair); run explicit ROW=i2iv6-esp later" ; fail=1 ;;
	all)
		run_row i2iinit-esp inet 192.0.5.1 192.0.5.2 aes128_cbc hmac_sha2_256 300 3600 0 || fail=1
		run_row i2ike-rekey inet 192.0.5.1 192.0.5.2 aes128_cbc hmac_sha2_256 60 3600 1  || fail=1
		;;
	*) echo "unknown ROW=$ROW"; exit 2 ;;
esac
echo "$SEP"
if [ "$fail" -eq 0 ]; then
	echo "FREEBSD-VNET-OK (row: $ROW)"
	exit 0
fi
echo "FREEBSD-VNET-FAIL (row: $ROW)"
exit 1
