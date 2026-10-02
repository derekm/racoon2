#!/bin/sh
# samples/freebsd-ci/freebsd-vnet-matrix.sh - FreeBSD vnet conformance MATRIX
# (renamed from ...-smoke.sh: this is a matrix runner, not a smoke test).
# Runs real iked<->iked tunnels across TWO vnet jails on ONE epair(4) per
# row (FreeBSD's analogues of Linux netns + veth), driven through the pfkey
# KM (if_pfkeyv2.c - auto-selected on FreeBSD; *linux*->xfrm, *->pfkey).
#
# First BSD leg that runs an actual tunnel matrix (the NetBSD legs are
# build+rc.d smoke only: "npf/pf/ipf is packet filter, not SAD/SPD").
# Rows mirror linux-matrix kinds with IDENTICAL algorithm tokens so pfkey
# parity can be asserted against xfrm on the same iked config:
#   i2iinit-*     initial IKE_SA + ESP child (mirrors kinds/i2iinit.sh rows)
#   i2idh-*       DH group rows (mirrors kinds/i2idh.sh non-charon rows)
#   i2ike-rekey   CREATE_CHILD child-SA rekey, new ESP SPI BOTH seats
#                 (mirrors i2ike.sh SPI gate; pfkey SADB UPDATE)
#   i2ineg-*      NEG rows: wrongpsk / idmismatch / a12strict / a12permit
#                 (mirrors kinds/i2i_neg.sh): a NEG(refuse) row PASSES when
#                 NO child SA appears in the window AND the refusal reason
#                 is in the responder log where expected.
#   expected-reject rows (neg=x): XCBC/CMAC ESP transforms that the FreeBSD
#                 15.1 kernel supported_aalgs[] does NOT ship.  racoon2 must
#                 refuse them at config-check ("not supported by kernel"),
#                 and the verdict requires that marker - so a future kernel
#                 that ADDS them turns the row red (child appears) and tells
#                 us to flip it to a positive accept test.  Never a SKIP.
#   i2iv6-esp     same tunnel over AF_INET6 (mirrors kinds/i2iv6.sh)
# Rows that are Linux-BOUND are deliberately NOT replicated: charon/
# strongSwan interop (no strongSwan in this testbed), netem drop/dup rows
# (Linux 'tc' only), mobike/cookie2 multi-address rows (need 2 SA endpoints),
# xfrm-only cells.  Every row PASSes only on a real per-jail SADB + a
# post-establishment data-plane ping through the tunnel (in/out `require`).
#
# PF_KEY SAD/SPD on stock FreeBSD is VIMAGE-virtualized PER-VNET JAIL
# (sys/netipsec/key.c): the ESP child is only visible from INSIDE each jail
# (host `setkey -D` is the host vnet and stays empty).  The two jails give
# each seat its own stack+port-500, matching the Linux matrix's netns.
#
# On blind CI runs every seat logs to /tmp/freeb-*; SADB+SPD dumps are
# retained per row.  Any row failing makes the run exit non-zero (a green
# first row must not mask a later failure).
set -eu
PREFIX="${PREFIX:-/usr/local/racoon2}"
SBIN="${PREFIX}/sbin"
export PATH="$PATH:/usr/local/sbin"
ROW="${ROW:-all}"

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
esp_up() { # esp_up $JAIL : count of *mature* esp tunnel SAs in that jail's SADB
	# A refused exchange leaves a `state=larval` SAD entry on the initiator
	# (no SADB_DELETE on abort) - that is expected, not an established child,
	# so count only entries whose state line says `mature`.
	jexec "$1" /usr/local/sbin/setkey -D 2>/dev/null \
		| grep -A1 'esp mode=tunnel' 2>/dev/null \
		| grep -c 'state=mature' || true
}

jails_teardown() {
	jexec $jr /bin/sh -c 'killall iked spmd 2>/dev/null' || true
	jexec $ji /bin/sh -c 'killall iked spmd 2>/dev/null' || true
	jail -r $jr 2>/dev/null || true
	jail -r $ji 2>/dev/null || true
	# stale admin/spmif sockets would block the NEXT row's daemons from binding
	rm -f /tmp/freeb/*-ctl* /tmp/freeb/*-spmif*
	rm -f /tmp/freeb-epair.txt
	# Per-row isolation: iked's resume dir (RACOON2_RESUME_DIR) is a
	# persistent host/shared path.  Left alone, EVERY row's iked restores the
	# PREVIOUS row's already-established IKE_SA (children=8 in the logs) and
	# rides resume/rekey instead of running a fresh IKE_AUTH - so NEG rows
	# (wrongpsk / idmismatch / strength) can never produce their refusal
	# marker because no authentication ever runs.  Clear the dumps per row so
	# every row is a virgin daemon with a clean SADB.
	rm -rf /tmp/freeb/init-resume /tmp/freeb/resp-resume
	# Truncate per-seat iked logs so diag()'s full-log greps only ever see
	# the CURRENT row's lines, never a previous row's pskey/ESTABLISHED/etc.
	rm -f /tmp/freeb/resp-iked.log /tmp/freeb/init-iked.log \
	      /tmp/freeb/resp-spmd.log /tmp/freeb/init-spmd.log
}

# gen_conf $SEAT $NAME $FAM $MY $PEER $IKE_ENC $IKE_PRF $IKE_DH \
#          $ESP_ENC $ESP_AUTH $MYID $PEERID $LFT $PSK_FILE $STRENGTH(on|"")
# Seat-specific: MY=my IP, PEER=peer IP.  Everything else is mirrored on
# both seats, matching the Linux matrix's identical-both-sides model.
gen_conf() {
	_seat=$1 _name=$2 _fam=$3 _my=$4 _peer=$5 _ienc=$6 _iprf=$7 _idh=$8 \
	_eesp=$9 _eaut=${10} _myid=${11} _peerid=${12} _lft=${13} _pskf=${14} _str=${15}
	# responder (jr) is passive: only the initiator's establish-sa triggers
	# the exchange, matching the proven matrix topology.
	_passive="off"; [ "$_seat" = "$jr" ] && _passive="on"
	[ "$_fam" = inet6 ] && _sfx=v6 || _sfx=""
	cat > /tmp/freeb/$_seat.conf <<EOF
interface {
	ike { $_my; };
	spmd { unix "/tmp/freeb/$_seat-spmif$_sfx"; };
	spmd_password "/tmp/freeb/spmd.pwd";
};
resolver { resolver off; };
remote matrix_$_seat {
	acceptable_kmp { ikev2; };
	ikev2 {
		passive $_passive;
		my_id fqdn "$_myid";
		peers_id fqdn "$_peerid";
		peers_ipaddr $_peer;
		kmp_enc_alg { $_ienc; };
		kmp_prf_alg { $_iprf; };
		kmp_hash_alg { $_iprf; };
		kmp_dh_group { $_idh; };
		kmp_auth_method { psk; };
		pre_shared_key "$_pskf";
		$_str
		dpd_delay 60 sec;
	};
	selector_index sel_in;
};
selector sel_out {
	direction outbound;
	src $_my; dst $_peer;
	policy_index pol;
};
selector sel_in {
	direction inbound;
	dst $_my; src $_peer;
	policy_index pol;
};
policy pol {
	action auto_ipsec;
	remote_index matrix_$_seat;
	ipsec_mode tunnel;
	ipsec_index { ipsec_e; };
	ipsec_level require;
	peers_sa_ipaddr $_peer;
	my_sa_ipaddr $_my;
};
ipsec ipsec_e {
	ipsec_sa_lifetime_time $_lft sec;
	sa_index esp_e;
};
sa esp_e {
	sa_protocol esp;
	esp_enc_alg { $_eesp; };
	esp_auth_alg { $_eaut; };
};
EOF
	echo "wrote /tmp/freeb/$_seat.conf"
}

# run_row NAME FAM HI HR IKE_ENC IKE_PRF IKE_DH ESP_ENC ESP_AUTH \
#          LFT_INIT LFT_RESP REKEY(0|1) NEG(a|r|p) STRENGTH_LINE
#   NEG=a : positive (child must come up + data-plane ping)
#   NEG=r : refuse   (child must NOT come up)
#   NEG=p : a12permit (stronger child with strength knob OFF -> must come up)
# STRENGTH_LINE e.g. 'parent_child_strength on;' (a12strict) or '' (default).
run_row() {
	_name=$1 _fam=$2 _hi=$3 _hr=$4 _ienc=$5 _iprf=$6 _idh=$7 \
	_eesp=$8 _eaut=$9 _lfti=${10} _lftr=${11} _rekey=${12} _neg=${13} _str=${14}
	echo "$SEP"
	echo "=== ROW $_name (fam=$_fam ike=$_ienc/$_iprf/$_idh esp=$_eesp/$_eaut neg=$_neg) ==="
	# kernel PF_KEY DPRINTFs (esp_init keylen/AEAD rejects) go to the console
	# when net.key.debug is set; set it BEFORE any SADB_ADD so a kernel
	# refusal on GCM/CTR/etc is visible in `dmesg` - never guess the reason.
	key_debug_on() {
		jexec $jr sysctl net.key.debug=7 >/dev/null 2>&1 || true
		jexec $ji sysctl net.key.debug=7 >/dev/null 2>&1 || true
		sleep 1
	}
	diag() {
		echo "--- raw responder SADB ---"; sed -n '1,30p' /tmp/freeb/resp-sadb.txt 2>/dev/null || true
		echo "--- raw initiator SADB ---"; sed -n '1,30p' /tmp/freeb/init-sadb.txt 2>/dev/null || true
		echo "--- responder SPD ---"; sed -n '1,20p' /tmp/freeb/resp-spd.txt 2>/dev/null || true
		# Instrument markers (proposal emit / wire transform / psk verify)
		# can sit far from the tail even on pos rows; grep FULL logs always.
		echo "--- iked instrument lines (full logs) ---"
		grep -E 'alg_to_proppair|child ENCR|pskey path|psk verify|keylen|transform_id' \
			/tmp/freeb/resp-iked.log 2>/dev/null | grep -vE '^[0-9a-f]{8}( |$)' | tail -25 || true
		grep -E 'alg_to_proppair|child ENCR|pskey path|psk verify|keylen|transform_id' \
			/tmp/freeb/init-iked.log 2>/dev/null | grep -vE '^[0-9a-f]{8}( |$)' | tail -25 || true
		# NEG rows: FULL iked logs matter (IKE_AUTH / ID-refusal lines are far
		# from the tail); the 25-line tail hid exactly that for wrongpsk.
		if [ "$_neg" = r ] || [ "$_neg" = x ]; then
			echo "--- responder iked (FULL) ---"; cat /tmp/freeb/resp-iked.log 2>/dev/null || true
			echo "--- initiator iked (FULL) ---"; cat /tmp/freeb/init-iked.log 2>/dev/null || true
		else
			echo "--- responder iked (tail) ---"; tail -25 /tmp/freeb/resp-iked.log 2>/dev/null || true
			echo "--- initiator iked (tail) ---"; tail -25 /tmp/freeb/init-iked.log 2>/dev/null || true
		fi
		echo "--- spmd logs ---"; cat /tmp/freeb/resp-spmd.log /tmp/freeb/init-spmd.log 2>/dev/null || true
		echo "--- host dmesg PF_KEY/ESP (net.key.debug=7, host buffer sees both vnets) ---"
		dmesg 2>/dev/null | grep -iE 'esp|ipsec|sadb|pfkey|gcm|keylen|auth' | tail -20 || true
		echo "--- per-jail dmesg (may be empty in a vnet jail; host reads above) ---"
		jexec $jr dmesg 2>/dev/null | grep -iE 'esp|ipsec|sadb|pfkey|gcm|keylen|auth' | tail -10 || true
		jexec $ji dmesg 2>/dev/null | grep -iE 'esp|ipsec|sadb|pfkey|gcm|keylen|auth' | tail -10 || true
	}
	# seed the endpoint locals from args; the inet6 branch overrides them.
	hr=$_hr; hi=$_hi
	# per row: keep a seat-local admin-sock suffix so the two seats never
	# collide; both seats use the same sock suffix (init vs resp).
	[ "$_fam" = inet6 ] && _sfx=v6 || _sfx=""
	jails_teardown

	echo "=== ONE epair, both ends into the two vnet jails ==="
	set +e; ifconfig epair create 2>/dev/null > /tmp/freeb-epair.txt; r=$?; set -e
	[ "$r" -eq 0 ] || { echo "FAIL: ifconfig epair create"; cat /tmp/freeb-epair.txt; exit 1; }
	ea=$(head -1 /tmp/freeb-epair.txt | awk '{print $1}' | tr -d ':')
	case "$ea" in
		*a) eb="${ea%a}b" ;;
		*b) eb="${ea%b}a" ;;
		*) echo "FAIL: unexpected epair '$ea'"; exit 1 ;;
	esac
	echo "epair ends: $ea (resp) / $eb (init)"
	jail -c name=$jr persist vnet vnet.interface="$ea" || { echo "FAIL: jail -c $jr"; exit 1; }
	jail -c name=$ji persist vnet vnet.interface="$eb" || { echo "FAIL: jail -c $ji"; exit 1; }

	if [ "$_fam" = inet6 ]; then
		# IPv6 row: assign v4 (for tooling) + a v6 /64 on each epair end; the
		# addresses ARE the IKE endpoints (2001:db8:1::1 / ::2).
		jexec $jr ifconfig "$ea" inet6 "2001:db8:1::1/64" up || { echo "FAIL: $jr v6"; exit 1; }
		jexec $ji ifconfig "$eb" inet6 "2001:db8:1::2/64" up || { echo "FAIL: $ji v6"; exit 1; }
		hi="2001:db8:1::2"; hr="2001:db8:1::1"
	else
		jexec $jr ifconfig "$ea" inet "$hr/24" up || { echo "FAIL: $jr addr"; exit 1; }
		jexec $ji ifconfig "$eb" inet "$hi/24" up || { echo "FAIL: $ji addr"; exit 1; }
	fi
	jexec $jr ifconfig lo0 inet 127.0.0.1/8 up 2>/dev/null || true
	jexec $ji ifconfig lo0 inet 127.0.0.1/8 up 2>/dev/null || true

	echo "=== throwaway CI PSK (random raw bytes, never the box PSK) + configs ==="
	install -d -m 0755 /tmp/freeb
	dd if=/dev/urandom of=/tmp/freeb/test.psk bs=32 count=1 2>/dev/null
	chmod 600 /tmp/freeb/test.psk
	printf 'ci-spmd-pw\n' > /tmp/freeb/spmd.pwd
	chmod 600 /tmp/freeb/spmd.pwd

	# NEG rows perturb ONE seat (differing key / id / strength).
	PSK_FI="/tmp/freeb/test.psk"   # initiator psk (overridden for wrongpsk)
	MYID_FI="r2init-matrix"        # initiator my_id (overridden for idmismatch)
	case "$_name" in
		*i2ineg-wrongpsk*)  PSK_FI="/tmp/freeb/neg.psk";
			dd if=/dev/urandom of=$PSK_FI bs=32 count=1 2>/dev/null; chmod 600 $PSK_FI ;;
		*i2ineg-idmismatch*) MYID_FI="racoon2-foreign" ;;
	esac
	# Both seats share the matrix ids; the responder always expects the
	# normal initiator id "r2init-matrix" — a NEG row mutates ONLY the
	# initiator's presented my_id (or its PSK file), never the responder's
	# expectation, else the refusal could not fire.
	gen_conf $jr "$_name" "$_fam" "$hr" "$hi" "$_ienc" "$_iprf" "$_idh" \
		"$_eesp" "$_eaut" "racoon2-matrix" "r2init-matrix" "$_lftr" "/tmp/freeb/test.psk" "$_str"
	gen_conf $ji "$_name" "$_fam" "$hi" "$hr" "$_ienc" "$_iprf" "$_idh" \
		"$_eesp" "$_eaut" "$MYID_FI" "racoon2-matrix" "$_lfti" "$PSK_FI" "$_str"
	# Conf-echo: prove the perturbed config is what iked loads (NEG rows
	# mutate only the initiator seat).  On a surprise child-appears this
	# shows whether the daemon really got the wrong PSK / foreign id.
	if [ "$_neg" = r ]; then
		echo "NEG conf-echo $_name: responder psk=$(ls -l /tmp/freeb/test.psk 2>/dev/null | awk '{print $5}')B initiator psk=$(ls -l "$PSK_FI" 2>/dev/null | awk '{print $5}')B"
		echo "NEG conf-echo $_name: responder expects peers_id=r2init-matrix; initiator my_id=$MYID_FI"
		grep -E 'pre_shared_key|my_id fqdn|peers_id fqdn' /tmp/freeb/r2vi.conf 2>/dev/null | sed 's/^/  init conf: /' || true
	fi
	# NB: ipsec lifetime for the initiator is short on rekey rows (below we
	# pass LFT_INIT < LFT_RESP so the initiator fires the CREATE_CHILD).

	# haul in kernel PF_KEY DPRINTFs (esp_init etc) BEFORE any SADB_ADD
	key_debug_on

	echo "=== start spmd + iked per seat (inside their vnet jails) ==="
	jexec $jr /bin/sh -c "env RACOON2_ADMIN_SOCK=/tmp/freeb/resp-ctl$_sfx RACOON2_RESUME_DIR=/tmp/freeb/resp-resume $SBIN/spmd -F -f /tmp/freeb/$jr.conf > /tmp/freeb/resp-spmd.log 2>&1 &" || true
	jexec $ji /bin/sh -c "env RACOON2_ADMIN_SOCK=/tmp/freeb/init-ctl$_sfx RACOON2_RESUME_DIR=/tmp/freeb/init-resume $SBIN/spmd -F -f /tmp/freeb/$ji.conf > /tmp/freeb/init-spmd.log 2>&1 &" || true
	i=0
	while [ "$i" -lt 15 ]; do
		[ -S "/tmp/freeb/resp-spmif$_sfx" ] && [ -S "/tmp/freeb/init-spmif$_sfx" ] && break
		i=$((i+1)); sleep 1
	done
	[ -S "/tmp/freeb/resp-spmif$_sfx" ] && [ -S "/tmp/freeb/init-spmif$_sfx" ] || echo "note: spmif sockets slow"
	sleep 1
	jexec $jr /bin/sh -c "env RACOON2_ADMIN_SOCK=/tmp/freeb/resp-ctl$_sfx RACOON2_RESUME_DIR=/tmp/freeb/resp-resume $SBIN/iked -F -f /tmp/freeb/$jr.conf -D 0x0001 -l /tmp/freeb/resp-iked.log > /tmp/freeb/resp-iked.out 2>&1 &" || true
	jexec $ji /bin/sh -c "env RACOON2_ADMIN_SOCK=/tmp/freeb/init-ctl$_sfx RACOON2_RESUME_DIR=/tmp/freeb/init-resume $SBIN/iked -F -f /tmp/freeb/$ji.conf -D 0x0001 -l /tmp/freeb/init-iked.log > /tmp/freeb/init-iked.out 2>&1 &" || true
	sleep 3

	echo "=== establish IKE/ESP from the initiator seat ==="
	jexec $ji $SBIN/ikedctl -s "/tmp/freeb/init-ctl$_sfx" establish-sa isakmp $_fam "$hi" "$hr" sel_out > /tmp/freeb/ctl.out 2>&1 || true

	up=0
	i=0
	if [ "$_neg" = r ] || [ "$_neg" = x ]; then
		# NEG(refuse) / expected-reject gate: child must NOT appear.
		# `r` = auth/id NEG (wrongpsk, idmismatch).  `x` = expected kernel
		# -gap rejection (XCBC/CMAC absent from supported_aalgs[]): refusal
		# must ALSO be proven by the config-check marker below, else a bare
		# timeout would fake a pass.
		rn=0; in=0
		while [ "$i" -lt 20 ]; do
			rn=$(esp_up $jr); in=$(esp_up $ji)
			if [ "$rn" -ge 1 ] || [ "$in" -ge 1 ]; then break; fi
			i=$((i+1)); sleep 1
		done
		if [ "$rn" -ge 1 ] || [ "$in" -ge 1 ]; then
			echo "FAIL (NEG): child SA appeared; refused exchange must stay empty"
		else
			grep -q "does not match peers id" /tmp/freeb/resp-iked.log 2>/dev/null && echo "row $_name: refusal reason in responder log (id/cert/psk)" || true
			grep -q "not supported by kernel" /tmp/freeb/resp-iked.log 2>/dev/null && echo "row $_name: kernel-gap refusal (config-check) confirmed" || true
			up=1
		fi
	else
		# positive / a12permit gate: child must come up.
		while [ "$i" -lt 45 ]; do
			rn=$(esp_up $jr); in=$(esp_up $ji)
			if [ "$rn" -ge 1 ] && [ "$in" -ge 1 ]; then up=1; break; fi
			i=$((i+1)); sleep 1
		done
	fi

	# DATA-PLANE gate (positive rows only): post-establishment ping THROUGH
	# the tunnel.  Under in/out `require` SPD a successful echo proves both
	# directions' SAs decrypt+encrypt — the real parity bar.
	TUN_OK=0
	if [ "$up" -eq 1 ] && [ "$_neg" != r ] && [ "$_neg" != x ]; then
		# FreeBSD /sbin/ping is IPv4-only; v6 rows must use ping6.
		if [ "$_fam" = inet6 ] && command -v ping6 >/dev/null 2>&1; then
			jexec $ji ping6 -c 1 -t 5 "$hr" > /tmp/freeb/ping-tun.txt 2>&1 || true
		else
			jexec $ji ping -c 1 -t 5 "$hr" > /tmp/freeb/ping-tun.txt 2>&1 || true
		fi
		if grep -qE '[1-9][0-9]* (packets )?received' /tmp/freeb/ping-tun.txt 2>/dev/null \
			&& ! grep -qE '0 packets received|100[.]0% packet loss|100% packet loss' /tmp/freeb/ping-tun.txt 2>/dev/null; then
			echo "row $_name: data-plane OK (post-establishment $ji->$hr ping through tunnel)"
			TUN_OK=1
		else
			echo "row $_name: FAIL data-plane (post-establishment ping did not transit)"
			cat /tmp/freeb/ping-tun.txt 2>/dev/null || true
		fi
	fi

	if [ "$up" -eq 1 ] && [ "$_neg" != r ] && [ "$_neg" != x ] && [ "$_rekey" -eq 1 ]; then
		echo "=== row $_name: child UP; assert CREATE_CHILD rekey (new ESP SPI both seats) ==="
		R0=$(spi $jr); I0=$(spi $ji)
		echo "initial SPIs R=[$(echo $R0 | tr '\n' ' ')] I=[$(echo $I0 | tr '\n' ' ')]"
		printf '%s\n' "$R0" > /tmp/freeb/R0.txt
		printf '%s\n' "$I0" > /tmp/freeb/I0.txt
		rekeyed=0
		i=0
		while [ "$i" -lt 90 ]; do
			spi $jr > /tmp/freeb/Rn.txt
			spi $ji > /tmp/freeb/In.txt
			nr=$(comm -13 /tmp/freeb/R0.txt /tmp/freeb/Rn.txt | grep -c spi || true)
			ni=$(comm -13 /tmp/freeb/I0.txt /tmp/freeb/In.txt | grep -c spi || true)
			if [ "$nr" -ge 1 ] && [ "$ni" -ge 1 ]; then
				echo "row $_name: CREATE_CHILD rekey new SPI both seats at ${i}s"
				rekeyed=1
				break
			fi
			i=$((i+1)); sleep 1
		done
		[ "$rekeyed" -eq 1 ] || { echo "FAIL row $_name: no new ESP SPI in 90s"; up=0; }
		if [ "$rekeyed" -eq 1 ]; then
			jexec $ji ping -c 1 -t 5 "$hr" > /tmp/freeb/ping-rekey.txt 2>&1 || true
			if grep -qE '[1-9][0-9]* (packets )?received' /tmp/freeb/ping-rekey.txt 2>/dev/null \
				&& ! grep -qE '0 packets received|100[.]0% packet loss|100% packet loss' /tmp/freeb/ping-rekey.txt 2>/dev/null; then
				echo "row $_name: post-rekey data-plane OK (still transiting)"
			else
				echo "FAIL row $_name: post-rekey data-plane did not transit"
				up=0
			fi
		fi
	fi

	echo "=== SAD/SPD dump from INSIDE each vnet jail (retained for diagnosis) ==="
	jexec $jr /usr/local/sbin/setkey -D > /tmp/freeb/resp-sadb.txt 2>&1 || true
	jexec $ji /usr/local/sbin/setkey -D > /tmp/freeb/init-sadb.txt 2>&1 || true
	jexec $jr /usr/local/sbin/setkey -DP > /tmp/freeb/resp-spd.txt 2>&1 || true
	jexec $ji /usr/local/sbin/setkey -DP > /tmp/freeb/init-spd.txt 2>&1 || true
	echo "responder jail ESP tunnel SAs: $(grep -cE 'esp mode=tunnel' /tmp/freeb/resp-sadb.txt 2>/dev/null || true)"
	echo "initiator jail ESP tunnel SAs: $(grep -cE 'esp mode=tunnel' /tmp/freeb/init-sadb.txt 2>/dev/null || true)"

	echo "=== verdict (row $_name) ==="
	# SA count is INFORMATIONAL ONLY (a healthy bidir tunnel can show 1
	# esp line per jail).  The authoritative gate is the data-plane ping /
	# NEG refusal, never the SA count.
	# On any FAILURE diag() (defined at top of run_row) dumps raw SADB,
	# both iked logs, and the kernel's netipsec dmesg reason - never guess
	# from the SA count alone.
	if [ "$_neg" = r ]; then
		# NEG(auth/id/strength) rows: refusal must be PROVEN, not just
		# inferred from an empty SADB.  A bare "no child" is coexistence
		# with the refusal (could be a timeout or an unrelated kernel
		# rejection, e.g. a12strict whose GCM child cannot install).  The
		# PASS requires the row's own refusal marker in the responder log.
		refusal=0
		case "$_name" in
			*i2ineg-wrongpsk*)   grep -q "authentication failure" /tmp/freeb/resp-iked.log 2>/dev/null && refusal=1 || true ;;
			*i2ineg-idmismatch*) grep -q "does not match peers id" /tmp/freeb/resp-iked.log 2>/dev/null && refusal=1 || true ;;
			*i2ineg-a12strict*)  grep -q "parent_child_strength on" /tmp/freeb/resp-iked.log 2>/dev/null && refusal=1 || true ;;
		esac
		if [ "$up" -eq 1 ] && [ "$refusal" -eq 1 ]; then
			echo "PASS freebsd-vnet $_name (NEG: refusal proven by responder log marker)"
			echo "CPL-ND : PASS $_name (pfkey KM, per-jail setkey -D empty + refusal marker)"
			jails_teardown
			return 0
		fi
		echo "FAIL freebsd-vnet $_name (NEG: refusal NOT proven)"
		echo "  up=$up refusal_marker=$refusal (expected: up=1 AND responder-log marker)"
		if [ "$up" -eq 0 ]; then
			echo "  child SA appeared - refusal did not fire (see resp-iked.log tail in diag)"
		else
			echo "  no child but the expected refusal marker is absent - refusal came from another cause (e.g. kernel), not this gate"
		fi
		cat /tmp/freeb/ctl.out 2>/dev/null || true
		diag
		echo "$SEP"
		jails_teardown
		return 1
	fi
	if [ "$_neg" = x ]; then
		# expected-reject (kernel gap): the transform is absent from the
		# FreeBSD kernel supported_aalgs[], so racoon2 MUST refuse at
		# config-check (ike_conf.c:4636 "not supported by kernel").  A PASS
		# requires BOTH no child AND that marker — a bare timeout must not
		# count as rejection.  When FreeBSD later ships XCBC/CMAC, the
		# config-check passes, a child appears and this FAILs: that red is
		# the signal to flip the row to a positive accept test (run ... a).
		if [ "$up" -eq 1 ] && grep -q "not supported by kernel" /tmp/freeb/resp-iked.log 2>/dev/null; then
			echo "PASS freebsd-vnet $_name (expected reject: kernel-gap refusal confirmed by config-check)"
			echo "CPL-XR : PASS $_name (expected kernel-gap rejection, non-vacuous: 'not supported by kernel' in responder log)"
			jails_teardown
			return 0
		fi
		echo "FAIL freebsd-vnet $_name (expected reject: kernel-gap refusal NOT confirmed)"
		if [ "$up" -eq 1 ]; then
			echo "WARN: no child SA but 'not supported by kernel' absent — refusal may be from a different cause; see diag"
		else
			echo "ALERT: child SA appeared — this transform is now accepted (FreeBSD kernel added support?); convert row from expected-reject to a positive accept test"
		fi
		diag
		echo "$SEP"
		jails_teardown
		return 1
	fi
	if [ "$up" -eq 1 ] && [ "$TUN_OK" -eq 1 ]; then
		lines=$(grep -cE 'esp mode=tunnel' /tmp/freeb/resp-sadb.txt /tmp/freeb/init-sadb.txt 2>/dev/null | awk -F: '{s+=$2} END{print s}')
		echo "PASS freebsd-vnet $_name (pfkey KM: $lines ESP tunnel SAs + data-plane $ji->$hr)"
		echo "CPL B1: PASS $_name (pfkey KM ESP child up AND transiting, per-jail setkey -D + tunnel ping)"
		jails_teardown
		return 0
	fi
	echo "FAIL freebsd-vnet $_name: no ESP tunnel SAs in either per-vnet SADB after timeout"
	echo "--- initiator ikedctl output ---"; cat /tmp/freeb/ctl.out 2>/dev/null || true
	diag
	echo "$SEP"
	jails_teardown
	return 1
}

fail=0
run() { run_row "$@" || fail=1; }

# Matrix rows.  Tokens match the Linux kinds verbatim so pfkey/xfrm parity
# is asserted on identical config.  REKEY rows: initiator lifetime short.
case "$ROW" in
	all)
		# --- i2iinit esp alg vectors (mirror linux i2iinit-esp-*) ---
		run i2iinit-esp-cbc128 inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp2048 aes128_cbc hmac_sha2_256 300 300 0 a ""
		run i2iinit-esp-cbc192 inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp2048 aes192_cbc hmac_sha2_256 300 300 0 a ""
		run i2iinit-esp-cbc256 inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp2048 aes256_cbc hmac_sha2_256 300 300 0 a ""
		run i2iinit-esp-gcm256 inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp2048 "aes_gcm, 256" non_auth 300 300 0 a ""
		run i2iinit-esp-sha384 inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp2048 aes256_cbc hmac_sha2_384 300 300 0 a ""
		run i2iinit-esp-sha512 inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp2048 aes256_cbc hmac_sha2_512 300 300 0 a ""
		# xcbc/cmac rows are EXPECTED-REJECT: FreeBSD 15.1 supported_aalgs[]
		# (sys/netipsec/key.c) lacks AES-XCBC-MAC/AES-CMAC, so racoon2 must
		# refuse at config-check.  The verdict gates on that marker, so when a
		# future FreeBSD kernel ships these transforms the row goes red (child
		# appears) and must be converted to a positive accept run.
		run i2iinit-esp-xcbc   inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp2048 aes256_cbc "aes_xcbc" 300 300 0 x ""
		run i2iinit-esp-cmac   inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp2048 aes256_cbc "aes_cmac" 300 300 0 x ""
		run i2iinit-esp-ctr    inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp2048 "aes_ctr" "non_auth" 300 300 0 a ""
		# --- i2iinit ike/prf vectors (mirror linux i2iinit-ike-*/prf-*) ---
		run i2iinit-ike-cbc192 inet 192.0.5.2 192.0.5.1 aes192_cbc hmac_sha2_256 modp2048 aes128_cbc hmac_sha2_256 300 300 0 a ""
		run i2iinit-ike-cbc256 inet 192.0.5.2 192.0.5.1 aes256_cbc hmac_sha2_256 modp2048 aes128_cbc hmac_sha2_256 300 300 0 a ""
		run i2iinit-ike-gcm256 inet 192.0.5.2 192.0.5.1 "aes_gcm, 256" hmac_sha2_256 modp2048 aes128_cbc hmac_sha2_256 300 300 0 a ""
		run i2iinit-prfsha384  inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_384 modp2048 aes128_cbc hmac_sha2_256 300 300 0 a ""
		run i2iinit-prfsha512  inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_512 modp2048 aes128_cbc hmac_sha2_256 300 300 0 a ""
		run i2iinit-prfxcbc    inet 192.0.5.2 192.0.5.1 aes128_cbc aes_xcbc modp2048 aes128_cbc hmac_sha2_256 300 300 0 a ""
		run i2iinit-prfcmac    inet 192.0.5.2 192.0.5.1 aes128_cbc aes_cmac modp2048 aes128_cbc hmac_sha2_256 300 300 0 a ""
		# --- i2idh DH groups (mirror linux i2idh non-charon rows) ---
		run i2idh-modp2048  inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp2048 aes128_cbc hmac_sha2_256 300 300 0 a ""
		run i2idh-modp3072  inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp3072 aes128_cbc hmac_sha2_256 300 300 0 a ""
		run i2idh-modp4096  inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp4096 aes128_cbc hmac_sha2_256 300 300 0 a ""
		run i2idh-modp6144  inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp6144 aes128_cbc hmac_sha2_256 300 300 0 a ""
		run i2idh-modp8192  inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp8192 aes128_cbc hmac_sha2_256 300 300 0 a ""
		run i2idh-ecp256    inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 ecp256  aes128_cbc hmac_sha2_256 300 300 0 a ""
		run i2idh-ecp384    inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 ecp384  aes128_cbc hmac_sha2_256 300 300 0 a ""
		run i2idh-ecp521    inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 ecp521  aes128_cbc hmac_sha2_256 300 300 0 a ""
		# --- rekey rows (CREATE_CHILD on short initiator lifetime) ---
		run i2ike-rekey     inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp2048 aes128_cbc hmac_sha2_256 60 3600 1 a ""
		# --- NEG rows (mirror linux i2i_neg.sh) ---
		run i2ineg-wrongpsk   inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp2048 aes128_cbc hmac_sha2_256 300 300 0 r ""
		run i2ineg-idmismatch inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp2048 aes128_cbc hmac_sha2_256 300 300 0 r ""
		run i2ineg-a12strict  inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp2048 "aes_gcm, 256" non_auth 300 300 0 r "parent_child_strength on;"
		run i2ineg-a12permit  inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp2048 "aes_gcm, 256" non_auth 300 300 0 a ""
		# --- IPv6 row (mirror linux i2iv6-esp) ---
		run i2iv6-esp          inet6 :: :: aes128_cbc hmac_sha2_256 modp2048 aes128_cbc hmac_sha2_256 300 300 0 a ""
		;;
	i2iinit-esp-cbc128) run_row i2iinit-esp-cbc128 inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp2048 aes128_cbc hmac_sha2_256 300 300 0 a "" ;;
	i2iinit-esp-gcm256) run_row i2iinit-esp-gcm256 inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp2048 "aes_gcm, 256" non_auth 300 300 0 a "" ;;
	i2iinit-esp-xcbc)  run_row i2iinit-esp-xcbc   inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp2048 aes256_cbc "aes_xcbc" 300 300 0 x "" ;;
	i2iinit-esp-cmac)  run_row i2iinit-esp-cmac   inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp2048 aes256_cbc "aes_cmac" 300 300 0 x "" ;;
	i2ineg-wrongpsk)   run_row i2ineg-wrongpsk   inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp2048 aes128_cbc hmac_sha2_256 300 300 0 r "" ;;
	i2ineg-idmismatch) run_row i2ineg-idmismatch inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp2048 aes128_cbc hmac_sha2_256 300 300 0 r "" ;;
	*) echo "unknown ROW=$ROW"; exit 2 ;;
esac
echo "$SEP"
if [ "$fail" -eq 0 ]; then
	echo "FREEBSD-VNET-OK (matrix: $ROW)"
	exit 0
fi
echo "FREEBSD-VNET-FAIL (matrix: $ROW)"
exit 1
