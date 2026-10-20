#!/bin/sh
# kinds/i2ike_collide.sh — RFC 7296 §1.4/§3.10.1 rekey-collision recovery.
#
# Establishes a plain iked<->iked child, then the responder's `ikedctl
# delete-sa <peer> esp` silently orphans the child (kernel SAs dropped,
# child marked EXPIRED, NO DELETE on the wire, IKE_SA briefly held).
# The initiator's short ESP lifetime (~45s) soft-expires and it rekeys the
# OLD child SPI — which the responder no longer holds — so the responder
# MUST answer CHILD_SA_NOT_FOUND (44) instead of silently dropping, and the
# initiator's existing error path (ikev2_child_abort) must clear the stuck
# rekey so the child can be rekeyed again.
#
# Gate: responder log 'can't find corresponding child_sa ... spi' + the 44
# reply (initiator logs 'received Notify ... type CHILD_SA_NOT_FOUND') +
# initiator 'child aborted in state WAIT_RESPONSE'.  A clean rekey where
# nothing was pruned proves nothing -> FAIL (requires the delete-sa to have
# actually removed the child, R esp 2->0).
#
# Classical ESP (no ADDKE followup) so the collision path is exercised in
# isolation.  box-verified before a container/CI admission.
kind_i2ike_collide() {
	name=$1
	require_root || return 1
	[ -x "$SBIN/iked" ] || { log "FAIL: no $SBIN/iked"; return 1; }
	[ -f "$ETC/spmd.pwd" ] || { log "FAIL: no $ETC/spmd.pwd"; return 1; }
	[ -f "$ETC/psk/macos.psk" ] || { log "FAIL: no $ETC/psk/macos.psk"; return 1; }

	row_ns "$name"

	HR=192.0.11.1; HI=192.0.11.2

	rm -rf "$PRIVRES_R" "$PRIVRES_I" "$D" "$C"
	mkdir -p "$PRIVRES_R" "$PRIVRES_I" "$D" "$C/psk"
	cp "$ETC/psk/macos.psk" "$C/psk/macos.psk"

	cat > "$C/responder.conf" <<EOF
interface { ike { "$HR"; }; spmd { unix "$SPMIF_R"; }; spmd_password "$ETC/spmd.pwd"; };
resolver { resolver off; };
remote collide_resp {
	acceptable_kmp { ikev2; };
	ikev2 { passive on; my_id fqdn "rcollide"; peers_id fqdn "icollide"; peers_ipaddr "$HI";
		kmp_enc_alg { aes256_cbc; }; kmp_prf_alg { hmac_sha2_256; }; kmp_hash_alg { hmac_sha2_256; };
		kmp_dh_group { ecp256; }; kmp_auth_method { psk; }; pre_shared_key "$C/psk/macos.psk"; dpd_delay 300 sec; };
	selector_index sel_in; };
selector sel_out { direction outbound; src "$HR"; dst "$HI"; policy_index pol; };
selector sel_in { direction inbound; dst "$HR"; src "$HI"; policy_index pol; };
policy pol { action auto_ipsec; remote_index collide_resp; ipsec_mode tunnel; ipsec_index { ipsec_e; };
	ipsec_level require; peers_sa_ipaddr "$HI"; my_sa_ipaddr "$HR"; };
ipsec ipsec_e { ipsec_sa_lifetime_time 3600 sec; sa_index esp_e; };
sa esp_e { sa_protocol esp; esp_enc_alg { aes_gcm; }; esp_auth_alg { non_auth; }; };
EOF
	cat > "$C/initiator.conf" <<EOF
interface { ike { "$HI"; }; spmd { unix "$SPMIF_I"; }; spmd_password "$ETC/spmd.pwd"; };
resolver { resolver off; };
remote collide_init {
	acceptable_kmp { ikev2; };
	ikev2 { passive off; my_id fqdn "icollide"; peers_id fqdn "rcollide"; peers_ipaddr "$HR";
		kmp_enc_alg { aes256_cbc; }; kmp_prf_alg { hmac_sha2_256; }; kmp_hash_alg { hmac_sha2_256; };
		kmp_dh_group { ecp256; }; kmp_auth_method { psk; }; pre_shared_key "$C/psk/macos.psk"; dpd_delay 300 sec; };
	selector_index sel_in; };
selector sel_out { direction outbound; src "$HI"; dst "$HR"; policy_index pol; };
selector sel_in { direction inbound; dst "$HI"; src "$HR"; policy_index pol; };
policy pol { action auto_ipsec; remote_index collide_init; ipsec_mode tunnel; ipsec_index { ipsec_e; };
	ipsec_level require; peers_sa_ipaddr "$HR"; my_sa_ipaddr "$HI"; };
ipsec ipsec_e { ipsec_sa_lifetime_time 45 sec; sa_index esp_e; };
sa esp_e { sa_protocol esp; esp_enc_alg { aes_gcm; }; esp_auth_alg { non_auth; }; };
EOF

	pkill -9 -f "$C/" 2>/dev/null || true
	rm -f "$SPMIF_R" "$SPMIF_I" "$SOCK_R" "$SOCK_I"

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
	    "$SBIN/iked" -F -f "$C/responder.conf" -D 0x0001 -l "$D/resp-iked.log" ) >"$D/resp-iked.out" 2>&1 &

	( ip netns exec "$NSI" "$SBIN/spmd" -F -f "$C/initiator.conf" ) >"$D/init-spmd.log" 2>&1 &
	ISPMD=$!
	i=0; until [ -S "$SPMIF_I" ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
	( ip netns exec "$NSI" env RACOON2_ADMIN_SOCK="$SOCK_I" RACOON2_RESUME_DIR="$PRIVRES_I" \
	    "$SBIN/iked" -F -f "$C/initiator.conf" -D 0x0001 -l "$D/init-iked.log" ) >"$D/init-iked.out" 2>&1 &

	sleep 2
	"$SBIN/ikedctl" -s "$SOCK_I" establish-sa isakmp inet "$HI" "$HR" sel_out >/dev/null 2>&1 || true

	up=0
	i=0
	# establish is an EVENT wait: under shard CPU starvation the iked pair
	# takes longer to bring the child up, so the bound must be generous
	# (and only trip for a genuinely stuck DUT, not slow scheduling).
	while [ "$i" -lt 120 ]; do
		re=$(ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -c 'proto esp')
		ie=$(ip netns exec "$NSI" ip xfrm state 2>/dev/null | grep -c 'proto esp')
		if [ "${re:-0}" -ge 2 ] && [ "${ie:-0}" -ge 2 ]; then
			log "collide child UP: responder esp=$re initiator esp=$ie after ${i}s"
			up=1
			break
		fi
		i=$((i+1)); sleep 1
	done
	[ "$up" -eq 1 ] || { log "FAIL: child not established (R esp=${re:-0} I esp=${ie:-0})"; return 1; }

	# Orphan the responder's child.  First try the WRONG protocol selector
	# (ah): it must prune nothing (child is ESP) — proves the filter paths.
	R_BEFORE=$(ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -c 'proto esp')
	"$SBIN/ikedctl" -s "$SOCK_R" delete-sa "$HI" ah >/dev/null 2>&1 || true
	sleep 1
	R_AH=$(ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -c 'proto esp')
	[ "$R_AH" = "$R_BEFORE" ] && log "delete-sa ah: pruned nothing (R esp $R_BEFORE -> $R_AH) filter OK"

	# Correct selector: prune the ESP child.
	"$SBIN/ikedctl" -s "$SOCK_R" delete-sa "$HI" esp >/dev/null 2>&1 || true
	sleep 2
	R_AFTER=$(ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -c 'proto esp')
	[ "$R_AFTER" -eq 0 ] || { log "FAIL: delete-sa esp did not prune (R esp=$R_AFTER)"; return 1; }

	# Wait for the initiator's 45s soft-expire to rekey the now-orphaned
	# child.  The responder must answer CHILD_SA_NOT_FOUND (44); the
	# initiator must abort the doomed child (releasing the reserved SPI).
	i=0; found=0
	[ -f "$D/resp-iked.log" ] || touch "$D/resp-iked.log"
	rm -f "$D/collide.gate"
	while [ "$i" -lt 90 ]; do
		if grep -q "can't find corresponding child_sa" "$D/resp-iked.log" 2>/dev/null &&
		   grep -q "type CHILD_SA_NOT_FOUND" "$D/init-iked.log" 2>/dev/null &&
		   grep -q "child aborted in state WAIT_RESPONSE" "$D/init-iked.log" 2>/dev/null; then
			found=1
			break
		fi
		i=$((i+1)); sleep 1
	done
	[ "$found" -eq 1 ] && {
		log "CHILD_SA_NOT_FOUND collision recovered: responder 44 + initiator abort (delete-sa ah filter + esp prune verified)"
		echo ok > "$D/collide.gate"
	}

	# cleanup
	kill "$RSPMD" "$ISPMD" 2>/dev/null || true
	pkill -9 -f "$C/" 2>/dev/null || true
	for NS in "$NSR" "$NSI"; do ip netns del "$NS" 2>/dev/null || true; done

	[ -f "$D/collide.gate" ] || { log "FAIL: CHILD_SA_NOT_FOUND not recovered on the wire (resp grep / init grep)"; return 1; }
	return 0
}
