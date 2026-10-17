#!/bin/sh
# kinds/i2iresume.sh — RFC 5723 SESSION RESUMPTION, self-consistent
# racoon2<->racoon2: the iked INITIATOR resumes a session from a ticket it
# stored on a prior IKE_AUTH, against the iked RESPONDER in the sibling
# netns (P2P veth; separate socket+XFRM stack).  Covers the full cycle on
# the iked initiator side — the same path i2ilw.sh exercises with a
# Libreswan pluto initiator, but here racoon2 is BOTH roles:
#
#   1. establish (IKE_SA_INIT + IKE_AUTH): responder mints
#      N(TICKET_LT_OPAQUE) (session_resumption on + ticket key);
#      initiator captures it and persists to RACOON2_RESUME_TICKET_DIR.
#   2. initiator spmd+iked restarted fresh (SA gone); ticket store kept.
#   3. re-establish: initiator presents the stored ticket via
#      IKE_SESSION_RESUME (exchange 38); racoon2 responder accepts it,
#      derives the resumed keys, answers the resumed IKE_AUTH with
#      prf(SK_pr,<message octets>); both SAs re-establish with NO full
#      IKE_AUTH re-run (no fresh TICKET_REQUEST path — the initiator
#      presents, so the box-verified i2ilw gate semantics apply).
#
# Gate (strict, the REAL resumed-session gate): BOTH
#   - responder logs 'accepted IKE_SESSION_RESUME ticket, resumed keys
#     derived, Nr sent' (exchange-38 accept, not a partial Nr), AND
#   - responder installs the resumed child (ESP states >= 2), AND
#   - initiator logs 'accepted resume response' + sends resumed IKE_AUTH
#     and the child is up on the initiator too, AND
#   - the resume pass did NOT re-run a full IKE_SA_INIT/AUTH (the
#     initiator's resume-present branch fired, not a fallback: the
#     'falling back to IKE_SA_INIT'-class fallback markers must be absent), AND
#   - up2 is measured after an xfrm state flush on BOTH seats, so it can
#     only be satisfied by SAs the RESUME actually installs (never stale
#     pass-1 ESP), mirroring the i2ilw drain.
# A pass that only reaches a partial exchange-38 Nr proves nothing; the
# resumed IKE_AUTH must establish.
#
# Variants (row name suffix):
#   -resume  the happy path above.
#   -nack    RFC 5723 s4.3.2 refusal + fallback (review H2): between the
#            passes the RESPONDER rotates its ticket key (the key file is
#            re-read per request), so the stored ticket no longer
#            authenticates.  Gate: the responder sends N(TICKET_NACK) in an
#            IKE_SESSION_RESUME (38) response; the initiator recognises it
#            (it only parses NACKs in an exchange-38 response), drops the
#            stored ticket and re-runs a full IKE_SA_INIT + IKE_AUTH on the
#            same SA; the child comes up; the responder never accepts the
#            old ticket; a NEW ticket is minted and stored in its place.
#   -reuse   RFC 5723 s4.3.1 "A reused ticket SHOULD be rejected" (review
#            M4): pass 2 resumes from the pass-1 ticket; pass 3 restarts the
#            initiator again with that SAME ticket restored into the store.
#            Gate: pass 2 resumes, pass 3 is NACKed as a reused ticket and
#            falls back to a full exchange that establishes.
#
# Needs session_resumption built in.  gate=addke rows run under the addke
# gate only (matching i2ike/i2ilw); the box and Fedora 44 container run
# them.  Initiator requires the RACOON2_RESUME_TICKET_DIR store to persist.
kind_i2iresume() {
	name=$1
	require_root || return 1
	[ -x "$SBIN/iked" ] || { log "FAIL: no $SBIN/iked"; return 1; }
	[ -f "$ETC/spmd.pwd" ] || { log "FAIL: no $ETC/spmd.pwd"; return 1; }
	[ -f "$ETC/psk/macos.psk" ] || { log "FAIL: no $ETC/psk/macos.psk"; return 1; }

	row_ns "$name"
	HR=192.0.7.1; HI=192.0.7.2
	# the -drain variant follows the responder's N(REDIRECT): explicit
	# opt-in on the initiator (accept_redirect, default off)
	I_REDIR=
	R_DBG=0x0001
	case "$name" in *-drain) I_REDIR='accept_redirect on;'; R_DBG=0x0003 ;; esac
	rm -rf "$PRIVRES_R" "$PRIVRES_I" "$D" "$C"; mkdir -p "$PRIVRES_R" "$PRIVRES_I" "$D" "$C"
	# ticket store dirs (initiator store + responder legacy crash dir)
	TKSTORE="$C/tickets"; mkdir -p "$TKSTORE"
	TKKEY="$C/ticketkey.bin"
	python3 -c 'import os,sys; sys.stdout.buffer.write(os.urandom(32))' > "$TKKEY" 2>/dev/null \
		|| dd if=/dev/urandom of="$TKKEY" bs=32 count=1 2>/dev/null
	chmod 600 "$TKKEY"

	cat > "$C/responder.conf" <<EOF
interface {
	ike { "$HR"; };
	spmd { unix "$SPMIF_R"; };
	spmd_password "$ETC/spmd.pwd";
};
resolver { resolver off; };
remote matrix_resp {
	acceptable_kmp { ikev2; };
	ikev2 {
		passive on;
		my_id fqdn "racoon2-sr";
		peers_id fqdn "racoon2-si";
		peers_ipaddr "$HI";
		kmp_enc_alg { aes256_cbc; };
		kmp_prf_alg { hmac_sha2_256; };
		kmp_hash_alg { hmac_sha2_256; };
		kmp_dh_group { ecp256; };
		kmp_auth_method { psk; };
		pre_shared_key "$ETC/psk/macos.psk";
		session_resumption on;
		session_resume_ticket_key "$TKKEY";
		session_resume_ticket_lifetime 3600;
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
	ipsec_sa_lifetime_time 60 sec;
	sa_index esp_e;
};
sa esp_e {
	sa_protocol esp;
	esp_enc_alg { aes256_cbc; };
	esp_auth_alg { hmac_sha2_256; };
};
EOF
	cat > "$C/initiator.conf" <<EOF
interface {
	ike { "$HI"; };
	spmd { unix "$SPMIF_I"; };
	spmd_password "$ETC/spmd.pwd";
};
resolver { resolver off; };
remote matrix_init {
	acceptable_kmp { ikev2; };
	ikev2 {
		passive off;
		$I_REDIR
		my_id fqdn "racoon2-si";
		peers_id fqdn "racoon2-sr";
		peers_ipaddr "$HR";
		kmp_enc_alg { aes256_cbc; };
		kmp_prf_alg { hmac_sha2_256; };
		kmp_hash_alg { hmac_sha2_256; };
		kmp_dh_group { ecp256; };
		kmp_auth_method { psk; };
		pre_shared_key "$ETC/psk/macos.psk";
		session_resumption on;
		dpd_delay 60 sec;
	};
	selector_index sel_out;
};
selector sel_out {
	direction outbound;
	src "$HI"; dst "$HR";
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
	ipsec_sa_lifetime_time 60 sec;
	sa_index esp_e;
};
sa esp_e {
	sa_protocol esp;
	esp_enc_alg { aes256_cbc; };
	esp_auth_alg { hmac_sha2_256; };
};
EOF

	# kill daemons by the unique per-run conf dir; fresh netns pair
	pkill -9 -f "$C/" 2>/dev/null || true
	rm -f "$SPMIF_R" "$SPMIF_I" "$SOCK_R" "$SOCK_I"

	for NS in "$NSR" "$NSI"; do
		ip netns del "$NS" 2>/dev/null || true
		ip netns add "$NS"
		ip netns exec "$NS" ip link set lo up
	done
	ip link add "$VR" type veth peer name "$VI"
	ip link set "$VR" netns "$NSR"; ip netns exec "$NSR" ip link set "$VR" up
	ip netns exec "$NSR" ip addr add "$HR/24" dev "$VR"
	ip link set "$VI" netns "$NSI"; ip netns exec "$NSI" ip link set "$VI" up
	ip netns exec "$NSI" ip addr add "$HI/24" dev "$VI"

	# UDP-allow rows so IKE is not captured by the tunnel policy
	for ns in "$NSR:$HR:$HI" "$NSI:$HI:$HR"; do
		NSX=${ns%%:*}; rest=${ns#*:}; LX=${rest%%:*}; PX=${rest#*:}
		for p in 500 4500; do
			ip netns exec "$NSX" ip xfrm policy add src "$PX"/32 dst "$LX"/32 proto udp sport "$p" dport "$p" dir in  ptype main action allow 2>/dev/null || true
			ip netns exec "$NSX" ip xfrm policy add src "$LX"/32 dst "$PX"/32 proto udp sport "$p" dport "$p" dir out ptype main action allow 2>/dev/null || true
		done
	done

	# start responder (spmd + iked)
	( ip netns exec "$NSR" "$SBIN/spmd" -F -f "$C/responder.conf" ) >"$D/resp-spmd.log" 2>&1 &
	i=0; until [ -S "$SPMIF_R" ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
	( ip netns exec "$NSR" env RACOON2_ADMIN_SOCK="$SOCK_R" RACOON2_RESUME_DIR="$PRIVRES_R" \
	    "$SBIN/iked" -F -f "$C/responder.conf" -D ${R_DBG:-0x0001} -l "$D/resp-iked.log" ) >"$D/resp-iked.out" 2>&1 &

	# start initiator (pass 1: fresh establish + capture the ticket)
	( ip netns exec "$NSI" "$SBIN/spmd" -F -f "$C/initiator.conf" ) >"$D/init-spmd.log" 2>&1 &
	i=0; until [ -S "$SPMIF_I" ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
	( ip netns exec "$NSI" env RACOON2_ADMIN_SOCK="$SOCK_I" \
	    RACOON2_RESUME_DIR="$PRIVRES_I" RACOON2_RESUME_TICKET_DIR="$TKSTORE" \
	    "$SBIN/iked" -F -f "$C/initiator.conf" -D 0x0001 -l "$D/init-iked.log" ) >"$D/init-iked.out" 2>&1 &
	sleep 2

	# PASS 1: fresh establish; responder mints ticket; initiator captures it
	"$SBIN/ikedctl" -s "$SOCK_I" establish-sa isakmp inet "$HI" "$HR" sel_out >/dev/null 2>&1 || true
	up1=0; i=0
	while [ "$i" -lt 45 ]; do
		re=$(ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -c 'proto esp')
		ie=$(ip netns exec "$NSI" ip xfrm state 2>/dev/null | grep -c 'proto esp')
		if [ "${re:-0}" -ge 2 ] && [ "${ie:-0}" -ge 2 ]; then
			log "i2iresume: pass1 child UP (resp=$re init=$ie) after ${i}s"
			up1=1; break
		fi
		i=$((i+1)); sleep 1
	done
	minted=$(grep -c 'issuing session-resumption ticket' "$D/resp-iked.log" 2>/dev/null || true)
	stored=$(ls "$TKSTORE"/r2tkt-* 2>/dev/null | wc -l)

	# PASS 2: restart the initiator FRESH (SA gone, netns kept) but KEEP the
	# ticket store.  The responder stays up with the same ticket key.
	# CRITICAL: wipe the initiator's LEGACY crash-resume dir first - the
	# ikev2_resume.c loader restores the old SA from RACOON2_RESUME_DIR on
	# restart, which resurrects the SA and skips the exchange-38 present
	# path entirely.  The store (RACOON2_RESUME_TICKET_DIR) is a separate
	# dir and must be kept so ikev2_initiator_start sees the ticket and
	# presents it.
	pkill -9 -f "$C/initiator.conf" 2>/dev/null || true
	rm -rf "$PRIVRES_I"; mkdir -p "$PRIVRES_I"
	rm -f "$SPMIF_I" "$SOCK_I"
	# keep a copy of the pass-1 ticket record (the -nack gate proves it was
	# replaced; the -reuse pass 3 presents it again)
	TK1=$(ls "$TKSTORE"/r2tkt-* 2>/dev/null | head -1)
	[ -n "$TK1" ] && cp -p "$TK1" "$C/pass1-ticket" 2>/dev/null
	case $name in
	*-nack)
		# rotate the responder's ticket key: same length, new bytes
		python3 -c 'import os,sys; sys.stdout.buffer.write(os.urandom(32))' > "$TKKEY.new" 2>/dev/null \
			|| dd if=/dev/urandom of="$TKKEY.new" bs=32 count=1 2>/dev/null
		chmod 600 "$TKKEY.new"; mv -f "$TKKEY.new" "$TKKEY"
		log "i2iresume: rotated responder ticket key before pass 2"
		;;
	*-drain)
		# RFC 5685 failover drain vs RFC 5723 resume: the responder is
		# DRAINING this peer (ikedctl drain-sa).  A ticketed reconnect
		# must be REFUSED at the responder resume handler — never resume
		# a session back onto the node being drained (that would defeat
		# the drain).  The refusal (NACK) forces the initiator to fall
		# back to a fresh IKE_SA_INIT, which the draining node then
		# answers N(REDIRECT) to a sibling.  Here (2-seat, no sibling)
		# we gate on: the drain-NACK was SENT, the resume was NOT
		# accepted, and the initiator dropped the ticket + began the
		# full-exchange fallback.  The drain-sa goes to a non-reachable
		# gw (no sibling in this 2-seat row); the point is the refusal,
		# not landing the redirected re-init.
		"$SBIN/ikedctl" -s "$SOCK_R" drain-sa "$HI" 192.0.99.7 >/dev/null 2>&1 || true
		log "i2iresume-drain: set drain-sa $HI -> 192.0.99.7 on responder before pass 2"
		;;
	esac
	sleep 2
	( ip netns exec "$NSI" "$SBIN/spmd" -F -f "$C/initiator.conf" ) >"$D/init2-spmd.log" 2>&1 &
	i=0; until [ -S "$SPMIF_I" ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
	( ip netns exec "$NSI" env RACOON2_ADMIN_SOCK="$SOCK_I" \
	    RACOON2_RESUME_DIR="$PRIVRES_I" RACOON2_RESUME_TICKET_DIR="$TKSTORE" \
	    "$SBIN/iked" -F -f "$C/initiator.conf" -D ${R_DBG:-0x0001} -l "$D/init2-iked.log" ) >"$D/init2-iked.out" 2>&1 &
	sleep 2

	# Drain: the pass-1 ESP SAs survive both the initiator's pkill -9
	# (SIGKILL never removes kernel XFRM state; the netns is kept) and the
	# responder's (never restarted, DPD 60s > poll).  Without a drain the
	# up2 poll below would satisfy re>=2 && ie>=2 from STALE pass-1 state
	# at i=0 — a vacuous up2 that passes even if the resumed IKE_AUTH
	# later fails.  Flush kernel ESP state on both seats so up2 can only
	# be raised by SAs the RESUME actually installs (the xfrm UDP-allow
	# *policies* are untouched by `state flush`).
	ip netns exec "$NSR" ip xfrm state flush 2>/dev/null || true
	ip netns exec "$NSI" ip xfrm state flush 2>/dev/null || true

	"$SBIN/ikedctl" -s "$SOCK_I" establish-sa isakmp inet "$HI" "$HR" sel_out >/dev/null 2>&1 || true
	up2=0; i=0
	while [ "$i" -lt 45 ]; do
		re=$(ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -c 'proto esp')
		ie=$(ip netns exec "$NSI" ip xfrm state 2>/dev/null | grep -c 'proto esp')
		if [ "${re:-0}" -ge 2 ] && [ "${ie:-0}" -ge 2 ]; then
			log "i2iresume: pass2 child UP (resp=$re init=$ie) after ${i}s"
			up2=1; break
		fi
		i=$((i+1)); sleep 1
	done

	# PASS 3 (-reuse only): restart the initiator once more and put the
	# pass-1 ticket back into its store, so it presents a ticket the
	# responder already accepted in pass 2.
	up3=0
	if [ "${name%-reuse}" != "$name" ]; then
		pkill -9 -f "$C/initiator.conf" 2>/dev/null || true
		rm -rf "$PRIVRES_I"; mkdir -p "$PRIVRES_I"
		rm -f "$SPMIF_I" "$SOCK_I"
		[ -n "$TK1" ] && [ -f "$C/pass1-ticket" ] && cp -p "$C/pass1-ticket" "$TK1"
		sleep 2
		( ip netns exec "$NSI" "$SBIN/spmd" -F -f "$C/initiator.conf" ) >"$D/init3-spmd.log" 2>&1 &
		i=0; until [ -S "$SPMIF_I" ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
		( ip netns exec "$NSI" env RACOON2_ADMIN_SOCK="$SOCK_I" \
		    RACOON2_RESUME_DIR="$PRIVRES_I" RACOON2_RESUME_TICKET_DIR="$TKSTORE" \
		    "$SBIN/iked" -F -f "$C/initiator.conf" -D 0x0001 -l "$D/init3-iked.log" ) >"$D/init3-iked.out" 2>&1 &
		sleep 2
		ip netns exec "$NSR" ip xfrm state flush 2>/dev/null || true
		ip netns exec "$NSI" ip xfrm state flush 2>/dev/null || true
		"$SBIN/ikedctl" -s "$SOCK_I" establish-sa isakmp inet "$HI" "$HR" sel_out >/dev/null 2>&1 || true
		i=0
		while [ "$i" -lt 45 ]; do
			re=$(ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -c 'proto esp')
			ie=$(ip netns exec "$NSI" ip xfrm state 2>/dev/null | grep -c 'proto esp')
			if [ "${re:-0}" -ge 2 ] && [ "${ie:-0}" -ge 2 ]; then
				log "i2iresume: pass3 child UP (resp=$re init=$ie) after ${i}s"
				up3=1; break
			fi
			i=$((i+1)); sleep 1
		done
	fi

	# GATES
	accepted=$(grep -c 'accepted IKE_SESSION_RESUME ticket' "$D/resp-iked.log" 2>/dev/null || true)
	presented=$(grep -c 'resuming via IKE_SESSION_RESUME\|accepted resume response' \
		"$D/init2-iked.log" 2>/dev/null || true)
	# the resume pass must NOT have fallen back to a full IKE_SA_INIT/AUTH
	# (the present branch fired instead).  Real fallback markers (only).
	fresh_auth=$(grep -c 'falling back to IKE_SA_INIT\|falling back to a full IKE_SA_INIT\|fresh IKE_SA_INIT' \
		"$D/init2-iked.log" 2>/dev/null || true)
	nack_sent=$(grep -c 'sent N(TICKET_NACK) in IKE_SESSION_RESUME (38) response' \
		"$D/resp-iked.log" 2>/dev/null || true)
	minted=$(grep -c 'issuing session-resumption ticket' "$D/resp-iked.log" 2>/dev/null || true)

	ok=0
	case $name in
	*-nack)
		nack_rcvd=$(grep -c 'received N(TICKET_NACK) in IKE_SESSION_RESUME response' \
			"$D/init2-iked.log" 2>/dev/null || true)
		fellback=$(grep -c 'ticket refused (TICKET_NACK); dropped stored ticket, falling back to a full IKE_SA_INIT' \
			"$D/init2-iked.log" 2>/dev/null || true)
		kfail=$(grep -c 'ticket validation failed' "$D/resp-iked.log" 2>/dev/null || true)
		# the full exchange re-ran on the initiator: an IKE_SA_INIT
		# response was processed and the SA reached ESTABLISHED
		full=$(grep -c 'INI_IKE_SA_INIT_SENT -> ' "$D/init2-iked.log" 2>/dev/null || true)
		TK2=$(ls "$TKSTORE"/r2tkt-* 2>/dev/null | head -1)
		replaced=0
		[ -n "$TK2" ] && [ -f "$C/pass1-ticket" ] && ! cmp -s "$TK2" "$C/pass1-ticket" && replaced=1
		log "i2iresume-nack gates: up1=$up1 up2=$up2 minted=$minted kfail=$kfail nack_sent=$nack_sent nack_rcvd=$nack_rcvd fellback=$fellback full=$full accepted=$accepted replaced=$replaced"
		if [ "$up1" -eq 1 ] && [ "$up2" -eq 1 ] \
		   && [ "${kfail:-0}" -ge 1 ] && [ "${nack_sent:-0}" -ge 1 ] \
		   && [ "${nack_rcvd:-0}" -ge 1 ] && [ "${fellback:-0}" -ge 1 ] \
		   && [ "${full:-0}" -ge 1 ] && [ "${accepted:-0}" -eq 0 ] \
		   && [ "${minted:-0}" -ge 2 ] && [ "$replaced" -eq 1 ]; then
			ok=1
			log "i2iresume-nack: rotated key -> TICKET_NACK (38) -> full IKE_SA_INIT fallback ESTABLISHED, new ticket stored"
		fi
		;; 
	*-drain)
		drain_nack=$(grep -c 'IKE_SESSION_RESUME from drained peer.*refusing (TICKET_NACK)' \
			"$D/resp-iked.log" 2>/dev/null || true)
		nack_rcvd=$(grep -c 'received N(TICKET_NACK) in IKE_SESSION_RESUME response' \
			"$D/init2-iked.log" 2>/dev/null || true)
		fellback=$(grep -c 'ticket refused (TICKET_NACK); dropped stored ticket, falling back to a full IKE_SA_INIT' \
			"$D/init2-iked.log" 2>/dev/null || true)
		full=$(grep -c 'INI_IKE_SA_INIT_SENT -> ' "$D/init2-iked.log" 2>/dev/null || true)
		# Assert the redirect itself, not just
		# the NACK.  The drained responder answers the fallback
		# IKE_SA_INIT with N(REDIRECT, 192.0.99.7) [drain] (-D 0x0003
		# TRACE), the initiator follows: it ferries the kept ticket to
		# 192.0.99.7 and presents IKE_SESSION_RESUME (38) there (a live
		# ticket diverts the re-drive to exchange 38; 192.0.99.7 is
		# unreachable in this 2-seat row, so nothing completes).
		redir_tx=$(grep -c 'RFC5685: redirecting this peer to 192.0.99.7 (offered REDIRECT_SUPPORTED) \[drain\]' \
			"$D/resp-iked.log" 2>/dev/null || true)
		retarget=$(grep -cE '192\.0\.99\.7\[500\].*RFC 5723: resuming via IKE_SESSION_RESUME' \
			"$D/init2-iked.log" 2>/dev/null || true)
		carried=$(grep -c 'RFC5685: carried resume ticket to redirected gw' \
			"$D/init2-iked.log" 2>/dev/null || true)
		log "i2iresume-drain gates: up1=$up1 minted=$minted drain_nack=$drain_nack nack_rcvd=$nack_rcvd fellback=$fellback full=$full accepted=$accepted presented=$presented redir_tx=$redir_tx retarget=$retarget carried=$carried"
		# The drained responder MUST refuse the ticketed resume (drain_nack)
		# and NOT accept it; the initiator must receive the NACK, drop the
		# stored ticket and begin the full-exchange fallback.  (up2 is not
		# required: the drain redirects the fallback IKE_SA_INIT to a
		# sibling that this 2-seat row does not provide.)
		if [ "$up1" -eq 1 ] && [ "${minted:-0}" -ge 1 ] \
		   && [ "${drain_nack:-0}" -ge 1 ] && [ "${nack_rcvd:-0}" -ge 1 ] \
		   && [ "${fellback:-0}" -ge 1 ] && [ "${full:-0}" -ge 1 ] \
		   && [ "${accepted:-0}" -eq 0 ] && [ "${presented:-0}" -ge 1 ] \
		   && [ "${redir_tx:-0}" -ge 1 ] && [ "${retarget:-0}" -ge 1 ] \
		   && [ "${carried:-0}" -ge 1 ]; then
			ok=1
			log "i2iresume-drain: drained responder refused the ticketed resume (NACK), resume NOT accepted, initiator fell back to full IKE_SA_INIT, was REDIRECTed to 192.0.99.7 and presented the carried ticket there"
		fi
		;;
	*-reuse)
		reuse_nack=$(grep -c 'ticket was already used' "$D/resp-iked.log" 2>/dev/null || true)
		nack_rcvd3=$(grep -c 'received N(TICKET_NACK) in IKE_SESSION_RESUME response' \
			"$D/init3-iked.log" 2>/dev/null || true)
		fellback3=$(grep -c 'falling back to a full IKE_SA_INIT' "$D/init3-iked.log" 2>/dev/null || true)
		log "i2iresume-reuse gates: up1=$up1 up2=$up2 up3=$up3 accepted=$accepted presented=$presented fresh_auth=$fresh_auth reuse_nack=$reuse_nack nack_sent=$nack_sent nack_rcvd3=$nack_rcvd3 fellback3=$fellback3"
		# pass 2 resumed (exactly one accept), pass 3 reuse was refused
		if [ "$up1" -eq 1 ] && [ "$up2" -eq 1 ] && [ "$up3" -eq 1 ] \
		   && [ "${accepted:-0}" -eq 1 ] && [ "${presented:-0}" -ge 1 ] \
		   && [ "${fresh_auth:-0}" -eq 0 ] && [ "${reuse_nack:-0}" -ge 1 ] \
		   && [ "${nack_sent:-0}" -ge 1 ] && [ "${nack_rcvd3:-0}" -ge 1 ] \
		   && [ "${fellback3:-0}" -ge 1 ]; then
			ok=1
			log "i2iresume-reuse: second presentation of one ticket NACKed, full exchange ESTABLISHED"
		fi
		;;
	*)
		silent_del=$(grep -c 'silently deleting the old IKE SA' \
			"$D/resp-iked.log" 2>/dev/null || true)
		log "i2iresume gates: up1=$up1 up2=$up2 minted=$minted stored=$stored accepted=$accepted presented=$presented fresh_auth=$fresh_auth nack_sent=$nack_sent silent_del=$silent_del"
		# up2/replacement requires RFC 5723 s4.3.4: on resume the old
		# ESTABLISHED IKE SA is silently deleted (gated by the responder's
		# silent-delete log).  This catches the display-order SPI
		# endianness bug that silently skipped the delete on LE hosts.
		if [ "$up1" -eq 1 ] && [ "$up2" -eq 1 ] \
		   && [ "${minted:-0}" -ge 1 ] && [ "${stored:-0}" -ge 1 ] \
		   && [ "${accepted:-0}" -ge 1 ] && [ "${presented:-0}" -ge 1 ] \
		   && [ "${fresh_auth:-0}" -eq 0 ] && [ "${nack_sent:-0}" -eq 0 ] \
		   && [ "${silent_del:-0}" -ge 1 ]; then
			ok=1
			log "i2iresume: RFC 5723 session resumption ESTABLISHED racoon2<->racoon2 (full resumed IKE_AUTH), old SA silently deleted"
		fi
		;;
	esac
	[ "$ok" -eq 1 ] || log "i2iresume: FAIL gates ($name)"

	# cleanup (scoped to this row's conf dir + netnss)
	pkill -9 -f "$C/" 2>/dev/null || true
	sleep 1
	ip netns del "$NSR" 2>/dev/null || true
	ip netns del "$NSI" 2>/dev/null || true
	ip link del "$VR" 2>/dev/null || true
	rm -rf "$PRIVRES_R" "$PRIVRES_I"

	[ "$ok" -eq 1 ] || {
		log "--- resp-iked.log (ticket/resume) ---"
		sed -n 's/.*\(TICKET\|accepted IKE_SESSION\|RFC 5723\|resumed\|err=\).*/\1: &/p' "$D/resp-iked.log" 2>/dev/null | tail -8
		log "--- init2-iked.log (present/resume) ---"
		grep -aiE 'resum|ticket|IKE_AUTH|established|accepted resume' "$D/init2-iked.log" 2>/dev/null | tail -10
		[ -f "$D/init3-iked.log" ] && { log "--- init3-iked.log ---"; grep -aiE 'resum|ticket|NACK|IKE_SA_INIT|established' "$D/init3-iked.log" 2>/dev/null | tail -10; }
		return 1
	}
	return 0
}
