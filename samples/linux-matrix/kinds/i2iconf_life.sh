#!/bin/sh
# kinds/i2iconf_life.sh — NDcPP v3.0e CONF-lifetime compliance rows (A7/A8).
#
# FCS_IPSEC_EXT.1.7/.1.8 (+ application notes 88/89): the IKE_SA and
# CHILD_SA lifetimes must be Security Administrator-CONFIGURABLE; a
# hardcoded limit fails even if the matrix rekeys.  This kind therefore
# sets DISTINCTIVE non-default values for both knobs and proves each is
# HONORED (not ignored back to the default):
#   - CHILD_SA  ipsec_sa_lifetime_time 53 sec -> SADB add carries
#     "lifetime soft time=NN bytes=0 hard time=53" (lft_hard_time is read
#     straight from the config knob, ikev2_child.c).  hard time == the
#     configured 53, not 0/default, proves the knob reaches the kernel.
#   - IKE_SA    kmp_sa_lifetime_time 37 sec -> the soft-expire timer
#     (soft = 37 * (0.8..0.9) ~= 30-33 s) fires ikev2_rekey_ikesa_initiate,
#     which logs "initiating IKE_SA rekey" (PLOG_INFO, ikev2_rekey.c).
#     A rekey inside the ~45 s window proves the 37 s knob drives the
#     timer; the 24 h default (86400) would never rekey there.
# Runs iked<->iked in OWN netnss (separate socket+XFRM), classical ESP
# (no ADDKE) so it runs on every build incl. an OpenSSL 3.0 Ubuntu.
kind_i2iconf_life() {
	name=$1
	require_root || return 1
	[ -x "$SBIN/iked" ] || { log "FAIL: no $SBIN/iked"; return 1; }
	[ -f "$ETC/spmd.pwd" ] || { log "FAIL: no $ETC/spmd.pwd"; return 1; }
	[ -f "$ETC/psk/macos.psk" ] || { log "FAIL: no $ETC/psk/macos.psk"; return 1; }

	NSR=i2cnf-r; NSI=i2cnf-i; VR=i2cnf-v-r; VI=i2cnf-v-i
	HR=192.0.5.1; HI=192.0.5.2
	PRIVRES_R=/tmp/r2-i2cnf-resume-r; PRIVRES_I=/tmp/r2-i2cnf-resume-i
	D=/tmp/r2-i2cnf; C=/tmp/r2-i2cnf-conf
	rm -rf "$PRIVRES_R" "$PRIVRES_I" "$D" "$C"; mkdir -p "$PRIVRES_R" "$PRIVRES_I" "$D" "$C"

	# CONF values the test asserts are HONORED (distinctive, non-default):
	# CHILD_SA hard-time must equal 53; IKE_SA soft-rekey must fire ~30s.
	cat > "$C/responder.conf" <<EOF
interface {
	ike { "$HR"; };
	spmd { unix "/tmp/spmif-i2cnf-r"; };
	spmd_password "$ETC/spmd.pwd";
};
resolver { resolver off; };
remote matrix_resp {
	acceptable_kmp { ikev2; };
	ikev2 {
		passive on;
		my_id fqdn "racoon2-matrix";
		peers_id fqdn "r2init-matrix";
		peers_ipaddr "$HI";
		kmp_enc_alg { aes256_cbc; };
		kmp_prf_alg { hmac_sha2_256; };
		kmp_hash_alg { hmac_sha2_256; };
		kmp_dh_group { ecp256; };
		kmp_auth_method { psk; };
		pre_shared_key "$ETC/psk/macos.psk";
		dpd_delay 60 sec;
	};
	selector_index sel_in;
};
selector sel_out {
	direction outbound;
	src "$HR"; dst "$HI";
	policy_index pol;
};
selector sel_in {
	direction inbound;
	dst "$HR"; src "$HI";
	policy_index pol;
};
policy pol {
	action auto_ipsec;
	remote_index matrix_resp;
	ipsec_mode tunnel;
	ipsec_index { ipsec_e; };
	ipsec_level require;
	peers_sa_ipaddr "$HI";
	my_sa_ipaddr "$HR";
};
ipsec ipsec_e {
	ipsec_sa_lifetime_time 53 sec;
	sa_index esp_e;
};
sa esp_e {
	sa_protocol esp;
	esp_enc_alg { aes_gcm; };
	esp_auth_alg { non_auth; };
};
EOF
	cat > "$C/initiator.conf" <<EOF
interface {
	ike { "$HI"; };
	spmd { unix "/tmp/spmif-i2cnf-i"; };
	spmd_password "$ETC/spmd.pwd";
};
resolver { resolver off; };
remote matrix_init {
	acceptable_kmp { ikev2; };
	ikev2 {
		passive off;
		my_id fqdn "r2init-matrix";
		peers_id fqdn "racoon2-matrix";
		peers_ipaddr "$HR";
		kmp_enc_alg { aes256_cbc; };
		kmp_prf_alg { hmac_sha2_256; };
		kmp_hash_alg { hmac_sha2_256; };
		kmp_dh_group { ecp256; };
		kmp_auth_method { psk; };
		pre_shared_key "$ETC/psk/macos.psk";
		dpd_delay 60 sec;
		kmp_sa_lifetime_time 37 sec;
	};
	selector_index sel_in;
};
selector sel_out {
	direction outbound;
	src "$HI"; dst "$HR";
	policy_index pol;
};
selector sel_in {
	direction inbound;
	dst "$HI"; src "$HR";
	policy_index pol;
};
policy pol {
	action auto_ipsec;
	remote_index matrix_init;
	ipsec_mode tunnel;
	ipsec_index { ipsec_e; };
	ipsec_level require;
	peers_sa_ipaddr "$HR";
	my_sa_ipaddr "$HI";
};
ipsec ipsec_e {
	ipsec_sa_lifetime_time 53 sec;
	sa_index esp_e;
};
sa esp_e {
	sa_protocol esp;
	esp_enc_alg { aes_gcm; };
	esp_auth_alg { non_auth; };
};
EOF

	# kill daemons by the unique per-run conf dir (it IS in their argv)
	pkill -9 -f "$C/" 2>/dev/null || true
	rm -f /tmp/spmif-i2cnf-r /tmp/spmif-i2cnf-i /tmp/iked.sock-i2cnf-r /tmp/iked.sock-i2cnf-i

	for NS in "$NSR" "$NSI"; do
		ip netns del "$NS" 2>/dev/null || true
		ip netns add "$NS"
		ip netns exec "$NS" ip link set lo up
	done
	ip link add "$VR" type veth peer name "$VI"
	ip link set "$VR" netns "$NSR"
	ip netns exec "$NSR" ip link set "$VR" up
	ip netns exec "$NSR" ip addr add "$HR/24" dev "$VR"
	ip link set "$VI" netns "$NSI"
	ip netns exec "$NSI" ip link set "$VI" up
	ip netns exec "$NSI" ip addr add "$HI/24" dev "$VI"

	# UDP-allow rows BEFORE any spmd so IKE is not tunnel-captured.
	for ns in "$NSR:$HR:$HI" "$NSI:$HI:$HR"; do
		NSX=${ns%%:*}; rest=${ns#*:}; LX=${rest%%:*}; PX=${rest#*:}
		for p in 500 4500; do
			ip netns exec "$NSX" ip xfrm policy add src "$PX"/32 dst "$LX"/32 proto udp sport "$p" dport "$p" dir in  ptype main action allow 2>/dev/null || true
			ip netns exec "$NSX" ip xfrm policy add src "$LX"/32 dst "$PX"/32 proto udp sport "$p" dport "$p" dir out ptype main action allow 2>/dev/null || true
		done
	done

	( ip netns exec "$NSR" "$SBIN/spmd" -F -f "$C/responder.conf" ) >"$D/resp-spmd.log" 2>&1 &
	i=0; until [ -S /tmp/spmif-i2cnf-r ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
	( ip netns exec "$NSR" env RACOON2_ADMIN_SOCK=/tmp/iked.sock-i2cnf-r RACOON2_RESUME_DIR="$PRIVRES_R" \
	    "$SBIN/iked" -F -f "$C/responder.conf" -D 0x0001 -l "$D/resp-iked.log" ) >"$D/resp-iked.out" 2>&1 &

	( ip netns exec "$NSI" "$SBIN/spmd" -F -f "$C/initiator.conf" ) >"$D/init-spmd.log" 2>&1 &
	i=0; until [ -S /tmp/spmif-i2cnf-i ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
	( ip netns exec "$NSI" env RACOON2_ADMIN_SOCK=/tmp/iked.sock-i2cnf-i RACOON2_RESUME_DIR="$PRIVRES_I" \
	    "$SBIN/iked" -F -f "$C/initiator.conf" -D 0x0001 -l "$D/init-iked.log" ) >"$D/init-iked.out" 2>&1 &

	sleep 2
	"$SBIN/ikedctl" -s /tmp/iked.sock-i2cnf-i establish-sa isakmp inet "$HI" "$HR" sel_out >/dev/null 2>&1 || true

	up=0; i=0
	while [ "$i" -lt 45 ]; do
		re=$(ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -c 'proto esp')
		ie=$(ip netns exec "$NSI" ip xfrm state 2>/dev/null | grep -c 'proto esp')
		if [ "${re:-0}" -ge 2 ] && [ "${ie:-0}" -ge 2 ]; then up=1; break; fi
		i=$((i+1)); sleep 1
	done
	log "child UP: resp es=$re init es=$ie after ${i}s (up=$up)"

	crash=0
	pkill -0 -f "$C/" 2>/dev/null || crash=1

	# ---- A8  CHILD_SA lifetime admin-configurable (note 88/89) ----------
	# The SADB add carries lft_hard_time = ipsec_sa_lifetime_time = the
	# configured 53 s (ikev2_child.c sets param->lft_hard_time from the
	# knob).  hard time == 53 (not 0 / not a hardcoded constant) proves
	# the admin knob is honored.
	a8=0; a8_line=
	for _lg in "$D/resp-iked.log" "$D/init-iked.log"; do
		if [ -f "$_lg" ]; then
			_lt=$(grep -aoE "lifetime soft time=[0-9]+ bytes=[0-9]+ hard time=53" "$_lg" | head -1)
			[ -n "$_lt" ] && { a8=1; a8_line="$_lt"; }
		fi
	done

	# ---- A7  IKE_SA lifetime admin-configurable (note 88/89) ------------
	# kmp_sa_lifetime_time 37 s on the initiator -> soft-expire timer at
	# ~30-33 s calls ikev2_rekey_ikesa_initiate, logged PLOG_INFO
	# "initiating IKE_SA rekey".  Firing inside the ~50 s window proves the
	# 37 s knob drives the timer (a hardcoded 24 h limit never fires).
	a7=0; a7_t=
	i=0
	while [ "$i" -lt 50 ]; do
		if grep -q "initiating IKE_SA rekey" "$D/init-iked.log" 2>/dev/null; then
			a7=1; a7_t="${i}s"; break
		fi
		i=$((i+1)); sleep 1
	done

	# verdicts — one CPL line per cell, quoting real observed output
	[ "$a8" -eq 1 ] && printf 'CPL A8: PASS CHILD_SA lifetime admin-configurable: ipsec_sa_lifetime_time 53s; SADB add "%s" (hard time == configured, not default)\n' "$a8_line"
	[ "$a8" -eq 0 ] && printf 'CPL A8: FAIL CHILD_SA lifetime knob not honored (no SADB hard time=53 in iked logs)\n'
	[ "$a7" -eq 1 ] && printf 'CPL A7: PASS IKE_SA lifetime admin-configurable: kmp_sa_lifetime_time 37s; soft-expire IKE_SA rekey logged "initiating IKE_SA rekey" at t=%s (24h default never fires there)\n' "$a7_t"
	[ "$a7" -eq 0 ] && printf 'CPL A7: FAIL IKE_SA lifetime knob not honored (no "initiating IKE_SA rekey" inside 50s of the 37s knob)\n'

	# per-cell blocker: A7/A8 are the reason this row exists
	[ "$a7" -eq 1 ] && [ "$a8" -eq 1 ] || { log "FAIL: CONF lifetime knob not honored (a7=$a7 a8=$a8 up=$up crash=$crash)"; return 1; }
	[ "$up" -eq 1 ] || { log "FAIL: child never came up (up=0)"; return 1; }
	[ "$crash" -eq 0 ] || { log "FAIL: a daemon died (crash=1)"; return 1; }

	log "PASS $name: CONF lifetime knobs honored (A7 IKE rekey t=${a7_t:-?} A8 hard-time=53, child up)"
	return 0
}
