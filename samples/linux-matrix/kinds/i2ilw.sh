#!/bin/sh
# kinds/i2ilw.sh — RFC 5723 session resumption INTEROP: a Libreswan pluto
# INITIATOR in its own netns against the racoon2 iked RESPONDER (SUT) in the
# sibling netns, on a P2P veth.  Covers the full resumed-session cycle:
#
#   1. pluto initiates -> racoon2 answers IKE_SA_INIT+IKE_AUTH, mints
#      N(TICKET_LT_OPAQUE) (responder must have session_resumption on and a
#      ticket key), Child SA up.
#   2. whack --terminate tears the IKE SA down.
#   3. whack --initiate again -> pluto presents the stored ticket via
#      IKE_SESSION_RESUME (exchange 38); racoon2 accepts it, derives the
#      resumed keys, answers the resumed IKE_AUTH with prf(SK_pr,<message
#      octets>), and BOTH SAs re-establish with NO full IKE_AUTH re-run.
#
# Gate: BOTH
#   - racoon2 responder logs 'RFC 5723: accepted IKE_SESSION_RESUME ticket,
#     resumed keys derived, Nr sent' AND installs the resumed child, AND
#   - pluto reports 'authenticated peer using authby=session-resume' AND
#     'established Child SA' on the resume pass.
# A pass that only reaches a partial exchange-38 Nr proves nothing; the
# resumed IKE_AUTH must establish.
#
# Requires libreswan (pluto 5.x with session resumption) + racoon2 built
# with session_resumption available.  gate=box until a counted box PASS.

kind_i2ilw() {
	name=$1
	require_root || return 1
	[ -x "$SBIN/iked" ] || { log "FAIL: no $SBIN/iked"; return 1; }
	[ -f "$ETC/spmd.pwd" ] || { log "FAIL: no $ETC/spmd.pwd"; return 1; }
	[ -x "$I2I_LW_PLUTO" ] || { log "FAIL: no libreswan pluto at $I2I_LW_PLUTO"; return 1; }

	row_ns "$name"
	HR=192.0.6.1; HI=192.0.6.2
	rm -rf "$PRIVRES_R" "$PRIVRES_I" "$D" "$C"; mkdir -p "$PRIVRES_R" "$PRIVRES_I" "$D" "$C"

	# Provision shared PSK + the responder's ticket key (real key bytes,
	# read from a file only — never on the command line, never logged).
	LW_PSK="$C/psk.bin"
	LW_TK="$C/ticketkey.bin"
	LW_PSK_TXT="${I2I_LW_PSK:-racoon2-libreswan-resume-0123456789abcdef}"
	printf '%s' "$LW_PSK_TXT" > "$LW_PSK"
	chmod 600 "$LW_PSK"
	# 32 raw octets for the AES-256 ticket key.
	python3 -c 'import os,sys; sys.stdout.buffer.write(os.urandom(32))' > "$LW_TK" 2>/dev/null \
		|| dd if=/dev/urandom of="$LW_TK" bs=32 count=1 2>/dev/null
	chmod 600 "$LW_TK"

	# --- racoon2 responder (SUT) conf ---
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
		my_id fqdn "racoon2-resume";
		peers_id fqdn "libreswan-resume";
		peers_ipaddr "$HI";
		kmp_enc_alg { aes256_cbc; };
		kmp_prf_alg { hmac_sha2_256; };
		kmp_hash_alg { hmac_sha2_256; };
		kmp_dh_group { modp2048; };
		kmp_auth_method { psk; };
		pre_shared_key "$LW_PSK";
		session_resumption on;
		session_resume_ticket_key "$LW_TK";
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
	ipsec_sa_lifetime_time 3600 sec;
	sa_index esp_e;
};
sa esp_e {
	sa_protocol esp;
	esp_enc_alg { aes256_cbc; };
	esp_auth_alg { hmac_sha2_256; };
};
EOF

	# --- Libreswan initiator seat ---
	LW_XAUTH_TODAY_CACHE_DIR=no
	mkdir -p "$C/lw-etc" "$C/lw-nss"
	cat > "$C/lw-etc/ipsec.conf" <<EOF
config setup
	logfile=/tmp/$name-ipsec.log
	protostack=netkey
	nssdir=$C/lw-nss
	ipsecdir=$C/lw-etc
	uniqueids=yes
	plutodebug=none

conn r2resume
	type=tunnel
	ikev2=insist
	left=$HI
	leftid=@libreswan-resume
	leftsubnet=$HI/32
	right=$HR
	rightid=@racoon2-resume
	rightsubnet=$HR/32
	authby=secret
	ike=aes256-sha2_256-modp2048
	esp=aes256-sha2_256
	ikelifetime=24h
	session-resumption=yes
	auto=add
EOF
	# PSK line by identity (same bytes as the iked seat).
	{
		printf '@libreswan-resume @racoon2-resume : PSK "%s"\n' "$LW_PSK_TXT"
	} > "$C/lw-etc/ipsec.secrets"
	chmod 600 "$C/lw-etc/ipsec.secrets"

	# kill any stale daemons from a prior run of this same-named row
	pkill -9 -f "$C/" 2>/dev/null || true
	rm -f "$SPMIF_R" "$SPMIF_I" "$SOCK_R" "$SOCK_I"

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

	# UDP-allow rows so IKE is not captured by the tunnel policy.
	for ns in "$NSR:$HR:$HI" "$NSI:$HI:$HR"; do
		NSX=${ns%%:*}; rest=${ns#*:}; LX=${rest%%:*}; PX=${rest#*:}
		for p in 500 4500; do
			ip netns exec "$NSX" ip xfrm policy add src "$PX"/32 dst "$LX"/32 proto udp sport "$p" dport "$p" dir in  ptype main action allow 2>/dev/null || true
			ip netns exec "$NSX" ip xfrm policy add src "$LX"/32 dst "$PX"/32 proto udp sport "$p" dport "$p" dir out ptype main action allow 2>/dev/null || true
		done
	done

	# racoon2 responder (spmd + iked)
	( ip netns exec "$NSR" "$SBIN/spmd" -F -f "$C/responder.conf" ) >"$D/resp-spmd.log" 2>&1 &
	RSPMD=$!
	i=0; until [ -S "$SPMIF_R" ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
	( ip netns exec "$NSR" env RACOON2_ADMIN_SOCK="$SOCK_R" RACOON2_RESUME_DIR="$PRIVRES_R" \
	    "$SBIN/iked" -F -f "$C/responder.conf" -D 0x0001 -l "$D/resp-iked.log" ) >"$D/resp-iked.out" 2>&1 &
	RSPMD_IKED=$!

	# Ensure an initialized NSS db exists BEFORE pluto starts.  pluto
	# rejects a bare certutil-created db (SEC_ERROR_BAD_DATABASE under its
	# read-only db mode) but accepts one built by libreswan's own
	# `ipsec initnss`.  Must run BEFORE the pluto launch below — pluto
	# reads the db at startup and dies if it is not present yet.
	if ! ls "$C/lw-nss"/cert9.db >/dev/null 2>&1; then
		LWIPSEC=$(command -v ipsec || echo /usr/sbin/ipsec)
		if [ -x "$LWIPSEC" ]; then
			"$LWIPSEC" initnss --nssdir "$C/lw-nss" >"$D/lw-nssinit.log" 2>&1 \
				|| { [ -f "$C/lw-nss/cert9.db" ] || { cat "$D/lw-nssinit.log" >&2; log "FAIL: ipsec initnss"; return 1; }; }
		else
			LWCERTUTIL=$(command -v certutil || echo /usr/bin/certutil)
			[ -x "$LWCERTUTIL" ] || { log "FAIL: libreswan needs `ipsec` (or certutil) to init its NSS db"; return 1; }
			"$LWCERTUTIL" -N -d "sql:$C/lw-nss" --empty-password >"$D/lw-nssinit.log" 2>&1
			[ -f "$C/lw-nss/cert9.db" ] || { cat "$D/lw-nssinit.log" >&2; log "FAIL: certutil NSS init"; return 1; }
		fi
	fi

	# libreswan pluto initiator (NSS db is initialized above)
	rm -f "$D/init-pluto.log" "$D/init-pluto.out"
	( ip netns exec "$NSI" "$I2I_LW_PLUTO" --nofork \
	    --ipsecdir "$C/lw-etc" --conf "$C/lw-etc/ipsec.conf" \
	    --secretsfile "$C/lw-etc/ipsec.secrets" --nssdir "$C/lw-nss" \
	    --logfile "$D/init-pluto.log" --stderrlog ) >"$D/init-pluto.out" 2>&1 &
	LWPLUTO=$!
	LWWHACK=${I2I_LW_WHACK:-/usr/libexec/ipsec/whack}
	# Wait until pluto is actually LISTENING before whack --initiate, else
	# whack fails with "need --listen before --initiate".  Poll the
	# pluto status socket (default /run/pluto/pluto.ctl in netns) rather
	# than raw process presence.
	i=0
	while [ "$i" -lt 30 ]; do
		if ip netns exec "$NSI" "$LWWHACK" --status >/dev/null 2>&1; then
			break
		fi
		i=$((i+1)); sleep 1
	done
	sleep 2

	lwwhack() { ip netns exec "$NSI" "$LWWHACK" --name r2resume "$@"; }

	# --- pass 1: establish, mint the ticket ---
	log "i2ilw: pass 1 initiate (establish + ticket)"
	lwwhack --initiate >"$D/pass1-whack.txt" 2>&1 || true
	cat "$D/pass1-whack.txt"
	up1=0; i=0
	while [ "$i" -lt 45 ]; do
		re=$(ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -c 'proto esp')
		if [ "${re:-0}" -ge 2 ]; then up1=1; log "i2ilw: pass1 child UP after ${i}s"; break; fi
		i=$((i+1)); sleep 1
	done
	grep -q 'issuing session-resumption ticket' "$D/resp-iked.log" 2>/dev/null \
		&& got_ticket=1 || got_ticket=0

	# --- pass 2: terminate, then re-initiate to RESUME ---
	log "i2ilw: pass 2 terminate + re-initiate (resume via exchange 38)"
	lwwhack --terminate >/dev/null 2>&1 || true
	sleep 2
	lwwhack --initiate >"$D/pass2-whack.txt" 2>&1 || true
	cat "$D/pass2-whack.txt"
	up2=0; i=0
	while [ "$i" -lt 45 ]; do
		re=$(ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -c 'proto esp')
		if [ "${re:-0}" -ge 2 ]; then up2=1; log "i2ilw: pass2 child UP after ${i}s"; break; fi
		i=$((i+1)); sleep 1
	done

	# --- gates ---
	accepted=$(grep -c 'accepted IKE_SESSION_RESUME ticket' "$D/resp-iked.log" 2>/dev/null || true)
	authby_resume=$(grep -c 'authenticated peer using authby=session-resume' "$D/init-pluto.log" 2>/dev/null || true)
	established=$(grep -c 'established Child SA using' "$D/init-pluto.log" 2>/dev/null || true)

	log "i2ilw gates: up1=$up1 up2=$up2 ticket=$got_ticket accepted=$accepted authby_resume=$authby_resume established=$established"
	ok=0
	if [ "$up1" -eq 1 ] && [ "$up2" -eq 1 ] && [ "$got_ticket" -eq 1 ] \
	   && [ "${accepted:-0}" -ge 1 ] && [ "${authby_resume:-0}" -ge 1 ] \
	   && [ "${established:-0}" -ge 1 ]; then
		ok=1
		log "i2ilw: RFC 5723 session resumption ESTABLISHED cross-vendor (Libreswan -> racoon2, full resumed IKE_AUTH)"
	else
		log "i2ilw: FAIL gates (up1=$up1 up2=$up2 ticket=$got_ticket accepted=${accepted:-0} authby_resume=${authby_resume:-0} established=${established:-0})"
	fi

	# cleanup (scoped to this row's conf dir + its named netnss)
	pkill -9 -f "$C/" 2>/dev/null || true
	sleep 1
	ip netns del "$NSR" 2>/dev/null || true
	ip netns del "$NSI" 2>/dev/null || true
	ip link del "$VR" 2>/dev/null || true
	rm -rf "$PRIVRES_R" "$PRIVRES_I"

	[ "$ok" -eq 1 ] || {
		log "--- resp-iked.log (ticket/resume) ---"
		sed -n 's/.*\(TICKET\|accepted IKE_SESSION\|RFC 5723\|resumed\|err=\).*/\1: &/p' "$D/resp-iked.log" 2>/dev/null | tail -8
		log "--- init-pluto.log (resume/establish) ---"
		grep -aiE 'session-resum|TICKET|IKE_AUTH|established|authenticated' "$D/init-pluto.log" 2>/dev/null | tail -10
		return 1
	}
	return 0
}
