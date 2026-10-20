#!/bin/sh
# kinds/i2ike_drain.sh — RFC 5685 drain live proof (steps 4a+4b).
#
# Two-seat iked<->iked (initiator=iked too).  Establishes a plain child,
# then the responder's `ikedctl drain-sa <peer> <gw>` (gw positional, no
# '-to' flag — ikedctl's getopt would eat it):
#
#   4b) SET a drain also SILENTLY CLOSES the peer's ESTABLISHED IKE_SA via
#       ikev2_abort (state -> DYING -> DEAD, no wire DELETE, reaper frees it),
#       which prunes the established child's responder-side kernel SAs
#       (R esp 2 -> 0).  Gate: responder log shows 'aborting ike_sa'
#       (PLOG_INFO, before any harness flush) AND R esp == 0.  A bare child
#       prune that leaves the IKE_SA ESTABLISHED is NOT enough — a surviving
#       DPD/rekey would re-home traffic back onto the draining node.
#
#   4a) A NEW IKE_SA_INIT from the drained peer (which now advertises
#       REDIRECT_SUPPORTED/16406 per 8175b5a) IS answered N(REDIRECT, gw)
#       with the drain target and does NOT re-establish against the draining
#       node.  Gate on the WIRE: the initiator's state retarget re-runs
#       IKE_SA_INIT against the drain gateway 192.0.99.7
#       ('192.0.99.7[500]… INI_IKE_SA_INIT_SENT' in init-iked.log) — an
#       address absent from every config, reachable only via the
#       N(REDIRECT)+Ni-verify+retarget follow path — AND R esp stays 0.
#       (The responder TRACE 'RFC5685: redirecting this peer to…[drain]' is
#       not emitted at the row's -D 0x0001 stream, so the initiator's wire
#       re-target is the authoritative gate, not that TRACE.)
#
# Classical ESP (no ADDKE).  gate=box: box-verified before a container/CI
# admission.
kind_i2ike_drain() {
	name=$1
	require_root || return 1
	[ -x "$SBIN/iked" ] || { log "FAIL: no $SBIN/iked"; return 1; }
	[ -f "$ETC/spmd.pwd" ] || { log "FAIL: no $ETC/spmd.pwd"; return 1; }
	[ -f "$ETC/psk/macos.psk" ] || { log "FAIL: no $ETC/psk/macos.psk"; return 1; }

	row_ns "$name"

	HR=192.0.11.1; HI=192.0.11.2
	# Synthetic drain gateway: must be a VALID IPv4 literal (the notify
	# encodes it; the initiator's follow re-drive to it is OUT of scope
	# for this row — it may fail to connect, which is fine and expected).
	# What we prove is the responder's decision + established-SA teardown.
	DGW=192.0.99.7
	# -noaccept variant: the initiator leaves
	# accept_redirect at its default (off), so it must NOT advertise
	# REDIRECT_SUPPORTED, the drained responder must drop (not redirect)
	# its IKE_SA_INIT, and it must never re-target to $DGW.
	I_REDIR='accept_redirect on;'; NOACC=0
	case "$name" in *-noaccept) I_REDIR=; NOACC=1 ;; esac

	rm -rf "$PRIVRES_R" "$PRIVRES_I" "$D" "$C"
	mkdir -p "$PRIVRES_R" "$PRIVRES_I" "$D" "$C/psk"
	cp "$ETC/psk/macos.psk" "$C/psk/macos.psk"

	cat > "$C/responder.conf" <<EOF
interface { ike { "$HR"; }; spmd { unix "$SPMIF_R"; }; spmd_password "$ETC/spmd.pwd"; };
resolver { resolver off; };
remote drain_resp {
	acceptable_kmp { ikev2; };
	ikev2 { passive on; my_id fqdn "rdrain"; peers_id fqdn "idrain"; peers_ipaddr "$HI";
		kmp_enc_alg { aes256_cbc; }; kmp_prf_alg { hmac_sha2_256; }; kmp_hash_alg { hmac_sha2_256; };
		kmp_dh_group { ecp256; }; kmp_auth_method { psk; }; pre_shared_key "$C/psk/macos.psk"; dpd_delay 300 sec; };
	selector_index sel_in; };
selector sel_out { direction outbound; src "$HR"; dst "$HI"; policy_index pol; };
selector sel_in { direction inbound; dst "$HR"; src "$HI"; policy_index pol; };
policy pol { action auto_ipsec; remote_index drain_resp; ipsec_mode tunnel; ipsec_index { ipsec_e; };
	ipsec_level require; peers_sa_ipaddr "$HI"; my_sa_ipaddr "$HR"; };
ipsec ipsec_e { ipsec_sa_lifetime_time 3600 sec; sa_index esp_e; };
sa esp_e { sa_protocol esp; esp_enc_alg { aes_gcm; }; esp_auth_alg { non_auth; }; };
EOF
	cat > "$C/initiator.conf" <<EOF
interface { ike { "$HI"; }; spmd { unix "$SPMIF_I"; }; spmd_password "$ETC/spmd.pwd"; };
resolver { resolver off; };
remote drain_init {
	acceptable_kmp { ikev2; };
	ikev2 { passive off; $I_REDIR my_id fqdn "idrain"; peers_id fqdn "rdrain"; peers_ipaddr "$HR";
		kmp_enc_alg { aes256_cbc; }; kmp_prf_alg { hmac_sha2_256; }; kmp_hash_alg { hmac_sha2_256; };
		kmp_dh_group { ecp256; }; kmp_auth_method { psk; }; pre_shared_key "$C/psk/macos.psk"; dpd_delay 300 sec; };
	selector_index sel_in; };
selector sel_out { direction outbound; src "$HI"; dst "$HR"; policy_index pol; };
selector sel_in { direction inbound; dst "$HI"; src "$HR"; policy_index pol; };
policy pol { action auto_ipsec; remote_index drain_init; ipsec_mode tunnel; ipsec_index { ipsec_e; };
	ipsec_level require; peers_sa_ipaddr "$HR"; my_sa_ipaddr "$HI"; };
ipsec ipsec_e { ipsec_sa_lifetime_time 3600 sec; sa_index esp_e; };
sa esp_e { sa_protocol esp; esp_enc_alg { aes_gcm; }; esp_auth_alg { non_auth; }; };
EOF

	pkill -9 -f "$C/" 2>/dev/null || true
	rm -f "$SPMIF_R" "$SPMIF_I" "$SOCK_R" "$SOCK_I"

	# Row cleanup for EVERY return path after the daemons are up: an early
	# `return 1` must not leave this row's iked/spmd retransmitting (extra
	# shard load) or its netns behind.
	_cl() {
		pkill -9 -f "$C/" 2>/dev/null || true
		for _ns in "$NSR" "$NSI"; do ip netns del "$_ns" 2>/dev/null || true; done
	}
	for NS in "$NSR" "$NSI"; do
		ip netns del "$NS" 2>/dev/null || true
		ip netns add "$NS"
		ip netns exec "$NS" ip link set lo up
		ip netns exec "$NS" ip xfrm state flush 2>/dev/null || true
		ip netns exec "$NS" ip xfrm policy flush 2>/dev/null || true
	done
	ip link add "$VR" type veth peer name "$VI"
	ip link set "$VR" netns "$NSR"
	ip netns exec "$NSR" ip link set "$VR" up
	ip netns exec "$NSR" ip addr add "$HR/24" dev "$VR"
	ip link set "$VI" netns "$NSI"
	ip netns exec "$NSI" ip link set "$VI" up
	ip netns exec "$NSI" ip addr add "$HI/24" dev "$VI"

	for ns in "$NSR:$HR:$HI" "$NSI:$HI:$HR"; do
		NSX=${ns%%:*}; rest=${ns#*:}; LX=${rest%%:*}; PX=${rest#*:}
		for p in 500 4500; do
			ip netns exec "$NSX" ip xfrm policy add src "$PX"/32 dst "$LX"/32 proto udp sport "$p" dport "$p" dir in  ptype main action allow 2>/dev/null || true
			ip netns exec "$NSX" ip xfrm policy add src "$LX"/32 dst "$PX"/32 proto udp sport "$p" dport "$p" dir out ptype main action allow 2>/dev/null || true
		done
	done

	( ip netns exec "$NSR" "$SBIN/spmd" -F -f "$C/responder.conf" ) >"$D/resp-spmd.log" 2>&1 &
	RSPMD=$!
	i=0; until [ -S "$SPMIF_R" ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
	( ip netns exec "$NSR" env RACOON2_ADMIN_SOCK="$SOCK_R" RACOON2_RESUME_DIR="$PRIVRES_R" \
	    "$SBIN/iked" -F -f "$C/responder.conf" -D 0x0003 -l "$D/resp-iked.log" ) >"$D/resp-iked.out" 2>&1 &

	( ip netns exec "$NSI" "$SBIN/spmd" -F -f "$C/initiator.conf" ) >"$D/init-spmd.log" 2>&1 &
	ISPMD=$!
	i=0; until [ -S "$SPMIF_I" ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
	( ip netns exec "$NSI" env RACOON2_ADMIN_SOCK="$SOCK_I" RACOON2_RESUME_DIR="$PRIVRES_I" \
	    "$SBIN/iked" -F -f "$C/initiator.conf" -D 0x0001 -l "$D/init-iked.log" ) >"$D/init-iked.out" 2>&1 &

	sleep 2
	"$SBIN/ikedctl" -s "$SOCK_I" establish-sa isakmp inet "$HI" "$HR" sel_out >/dev/null 2>&1 || true

	up=0
	i=0
	# establish is an EVENT wait: under shard CPU load the iked pair takes
	# longer to bring the child up, so the bound must be generous and only
	# trip for a genuinely stuck DUT.
	while [ "$i" -lt 120 ]; do
		re=$(ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -c 'proto esp')
		ie=$(ip netns exec "$NSI" ip xfrm state 2>/dev/null | grep -c 'proto esp')
		if [ "${re:-0}" -ge 2 ] && [ "${ie:-0}" -ge 2 ]; then
			log "drain child UP: responder esp=$re initiator esp=$ie after ${i}s"
			up=1
			break
		fi
		i=$((i+1)); sleep 1
	done
	[ "$up" -eq 1 ] || { log "FAIL: child not established (R esp=${re:-0} I esp=${ie:-0})"; _cl; return 1; }

	# Data-plane proof BEFORE the drain: the child
	# must carry traffic both ways while it is still up, so the xfrm audit
	# sees the inbound+outbound counters rise on both seats.  Doing it here
	# (not racing the harness probe against the drain's SA teardown) is
	# what keeps this row free of any xfrm_audit.tsv traffic exemption.
	i2i_dataplane "$NSI" "$HR" "$name pre-drain" || { _cl; return 1; }

	# 4b: drain-sa SET must tear down the established IKE_SA locally
	# (gw is positional: a "-to" flag would be eaten by ikedctl's
	# top-level getopt before the drain-sa branch runs).
	R_BEFORE=$(ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -c 'proto esp')
	"$SBIN/ikedctl" -s "$SOCK_R" drain-sa "$HI" "$DGW" \
	    >"$D/drain-sa.out" 2>&1
	log "drain-sa exit=$? (out: $(cat "$D/drain-sa.out" 2>/dev/null | tr '\n' ' '))"
	# 4b gate (the REAL one): the drain must SILENTLY CLOSE the established
	# IKE_SA too, not just prune its children.  ikev2_abort logs
	# 'aborting ike_sa' at PLOG_INFO (visible at -D 0x0001) and sets the
	# SA DYING->DEAD with NO wire DELETE; the reaper frees it.  If the SA
	# were left ESTABLISHED (the bug), a surviving DPD/rekey would re-home
	# traffic back onto the draining node and never hit the IKE_SA_INIT
	# redirect.
	i=0; closed=0
	[ -f "$D/resp-iked.log" ] || touch "$D/resp-iked.log"
	while [ "$i" -lt 20 ]; do
		if grep -q "aborting ike_sa" "$D/resp-iked.log" 2>/dev/null; then
			closed=1
			break
		fi
		i=$((i+1)); sleep 1
	done
	# Event-wait: the kernel ESP SAs are torn down ASYNCHRONOUSLY after
	# 'aborting ike_sa' and can lag under shard load; poll R esp to 0
	# instead of sampling once (a 2->1 at a single sample was a false fail).
	R_AFTER=-1
	i=0
	while [ "$i" -lt 30 ]; do
		R_AFTER=$(ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -c 'proto esp')
		[ "${R_AFTER:-1}" -eq 0 ] && break
		i=$((i+1)); sleep 1
	done
	[ "$R_BEFORE" -ge 2 ] || { log "FAIL: unexpected pre-drain R esp=$R_BEFORE"; _cl; return 1; }
	[ "$R_AFTER" -eq 0 ] || { log "FAIL: drain-sa did not tear down established SA (R esp $R_BEFORE -> $R_AFTER)"; _cl; return 1; }
	[ "$closed" -eq 1 ] || { log "FAIL: drain-sa did NOT silently close the established IKE_SA (no 'aborting ike_sa') — a surviving DPD/rekey would re-home traffic onto the draining node"; _cl; return 1; }
	log "drain-sa SET: established IKE_SA silently closed (abort) + R esp $R_BEFORE -> $R_AFTER"

	# 4a: a NEW IKE_SA_INIT from the drained peer is answered REDIRECT and
	# does NOT re-establish against the draining node.  The drain closed
	# its OWN side silently (no wire DELETE), so the initiator still
	# considers its session live and would no-op a bare establish-sa.
	# Force a genuine re-initiate by flushing the initiator's SA (its own
	# local teardown) and re-establishing.
	"$SBIN/ikedctl" -s "$SOCK_I" flush-sa isakmp >/dev/null 2>&1 || true
	sleep 1
	"$SBIN/ikedctl" -s "$SOCK_I" establish-sa isakmp inet "$HI" "$HR" sel_out >/dev/null 2>&1 || true
	# Gate on the WIRE (not a log TRACE): the initiator must have received
	# N(REDIRECT, DGW), verified the echoed Ni, and FIRST-hand re-driven
	# IKE_SA_INIT to the drain gateway — i.e. it sends IKE_SA_INIT to
	# $DGW (192.0.99.7).  That is only reachable via the redirect-follow
	# path (receive+verify+retarget+re-drive); a bare establish would
	# target $HR.  The responder's own drain TRACE is not emitted at the
	# row's -D 0x0001 debug stream, so the initiator's re-target to the
	# drain gateway is the authoritative, direct measurement.
	i=0; followed=0
	[ -f "$D/init-iked.log" ] || touch "$D/init-iked.log"
	while [ "$i" -lt 20 ]; do
		# Anchor on the specific wire evidence: the initiator state
		# retarget "… - <DGW>[500]… INI_IKE_SA_INIT_SENT" — the remote
		# field moves to the drain gateway and the state machine re-runs
		# IKE_SA_INIT against it (a bare $DGW match anywhere would be
		# loose).  Only the redirect-follow path re-drives against an
		# address absent from every config.
		if grep -E "${DGW}\[500\].*INI_IKE_SA_INIT_SENT" \
		    "$D/init-iked.log" 2>/dev/null; then
			followed=1
			break
		fi
		i=$((i+1)); sleep 1
	done
	R_ESP2=$(ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -c 'proto esp')
	if [ "$NOACC" = 1 ]; then
		_rc=0
		[ "$followed" -eq 0 ] || { log "FAIL: accept_redirect off but the initiator re-targeted to $DGW"; _rc=1; }
		grep -q "drained peer did not offer REDIRECT_SUPPORTED" "$D/resp-iked.log" 2>/dev/null \
			|| { log "FAIL: drained responder did not log the no-16406 drop"; _rc=1; }
		grep -q "peer supports redirection (REDIRECT_SUPPORTED" "$D/resp-iked.log" 2>/dev/null \
			&& { log "FAIL: initiator advertised REDIRECT_SUPPORTED with accept_redirect off"; _rc=1; }
		[ "$R_ESP2" -eq 0 ] || { log "FAIL: drained peer re-established against draining node (R esp=$R_ESP2)"; _rc=1; }
		kill "$RSPMD" "$ISPMD" 2>/dev/null || true
		pkill -9 -f "$C/" 2>/dev/null || true
		for NS in "$NSR" "$NSI"; do ip netns del "$NS" 2>/dev/null || true; done
		[ "$_rc" -eq 0 ] && log "drain -noaccept OK: no 16406 offered, drained responder dropped the IKE_SA_INIT, no re-target"
		return $_rc
	fi
	# the responder TRACE (-D 0x0003) proves the initiator advertised 16406
	# (accept_redirect on); the -noaccept variant asserts its absence.
	grep -q "peer supports redirection (REDIRECT_SUPPORTED" "$D/resp-iked.log" 2>/dev/null \
		|| { log "FAIL: initiator with accept_redirect on did not advertise REDIRECT_SUPPORTED"; _cl; return 1; }
	[ "$followed" -eq 1 ] || { log "FAIL: drained peer's new IKE_SA_INIT was not answered REDIRECT to $DGW (initiator never re-targeted to drain gw)"; _cl; return 1; }
	[ "$R_ESP2" -eq 0 ] || { log "FAIL: drained peer re-established against draining node (R esp=$R_ESP2)"; _cl; return 1; }

	log "drain live proof OK: established SA torn down on SET + new IKE_SA_INIT answered REDIRECT [drain], no re-establish on draining node"
	echo ok > "$D/drain.gate"

	# cleanup
	kill "$RSPMD" "$ISPMD" 2>/dev/null || true
	pkill -9 -f "$C/" 2>/dev/null || true
	for NS in "$NSR" "$NSI"; do ip netns del "$NS" 2>/dev/null || true; done

	[ -f "$D/drain.gate" ] || { log "FAIL: drain proof incomplete"; return 1; }
	return 0
}
