#!/bin/sh
# kinds/i2ilwpeer.sh -- IKEv2 interop against Libreswan pluto, the Libreswan
# counterpart of the strongSwan charon seat in i2i_peer.sh.  racoon2 iked
# (spmd + iked) runs in the row's -r netns, pluto in the -i netns, joined by
# a private veth.  Everything pluto touches lives under the row's $C:
# ipsec.conf, ipsec.secrets, the NSS db and the run dir with its whack
# control socket (--rundir / --ctlsocket), so no host /etc/ipsec*, /run/pluto
# or service is used.
#
# An sspeer-* row runs the SAME scenarios with a strongSwan charon seat
# (i2i_charon_run from i2i_peer.sh: private swanctl root, vici socket and
# /run bind in a private mount ns) instead of pluto.
#
# Row name selects the scenario (suffix -i: iked initiates, -r: pluto does):
#   lwpeer-psk-i / lwpeer-psk-r   PSK IKE_SA + Child SA, ESP both ways
#   lwpeer-frag-i                 RFC 7383: 250-octet IDi and IDr push iked's
#                                 IKE_AUTH past 576 octets; the wire must
#                                 carry >= 2 SKF (payload 53) IKE_AUTH
#                                 datagrams from iked and the SA must come up
#   lwpeer-childrekey-i           iked ipsec_sa_lifetime_time 30 s: a
#                                 CREATE_CHILD_SA (exch 36) on the wire, a new
#                                 ESP SPI pair installed, the old pair gone,
#                                 IKE SPIs unchanged
#   lwpeer-childrekeypfs-i        as childrekey, with PFS on both sides (iked
#                                 need_pfs on, pluto pfs=yes, ESP modp2048)
#   lwpeer-pfsmismatch-i          NEGATIVE, realistic misconfig: pluto's
#                                 default pfs=yes vs iked need_pfs off.  The
#                                 rekey is rejected (NO_PROPOSAL_CHOSEN);
#                                 iked must arm bounded backoff and send
#                                 1..3 CREATE_CHILD_SA requests in 50 s
#   lwpeer-ikerekey-i             iked kmp_sa_lifetime_time 30 s: exch 36 and
#                                 a NEW IKE SPI pair carries later traffic
#   lwpeer-delete-i               pluto (responder) terminates: an
#                                 INFORMATIONAL (exch 37) from pluto, and
#                                 iked removes every ESP SA within 15 s
#
# Gates are wire facts (ikesniff.py in iked's netns) and kernel XFRM state,
# never daemon log wording alone.  Requires pluto at $I2I_LW_PLUTO.
kind_i2ilwpeer() {
	name=$1
	require_root || return 1
	[ -x "$SBIN/iked" ] || { log "FAIL: no $SBIN/iked"; return 1; }
	[ -f "$ETC/spmd.pwd" ] || { log "FAIL: no $ETC/spmd.pwd"; return 1; }
	case $name in sspeer-*) PEER=ss ;; *) PEER=lw ;; esac
	if [ "$PEER" = lw ]; then
		[ -x "$I2I_LW_PLUTO" ] || { log "FAIL: no libreswan pluto at $I2I_LW_PLUTO"; return 1; }
		[ -x "$I2I_LW_WHACK" ] || { log "FAIL: no libreswan whack at $I2I_LW_WHACK"; return 1; }
	else
		[ -z "$I2I_SWANCTL_FATAL" ] || { log "FAIL: $I2I_SWANCTL_FATAL"; return 1; }
		[ -x "$I2I_CHARON_BIN" ] || { log "FAIL: no charon at $I2I_CHARON_BIN"; return 1; }
	fi
	command -v python3 >/dev/null 2>&1 || { log "FAIL: no python3 (ikesniff.py)"; return 1; }

	case $name in
	*-i) role=i ;; *-r) role=r ;;
	*) log "FAIL: $name: row name must end in -i or -r"; return 1 ;;
	esac
	scen=${name#??peer-}; scen=${scen%-?}

	row_ns "$name"
	HR=192.0.7.1; HI=192.0.7.2
	rm -rf "$PRIVRES_R" "$D" "$C"; mkdir -p "$PRIVRES_R" "$D" "$C/lw-etc" "$C/lw-nss" "$C/lw-run"
	chmod 700 "$C/lw-run"

	R_ID=racoon2-lw; L_ID=libreswan-lw
	if [ "$scen" = frag ]; then
		# A long FQDN IDi plus a multi-transform ESP proposal take
		# iked's encrypted IKE_AUTH request past the 576-octet IPv4
		# floor at which iked fragments (RFC 7383 s2.5).
		_pad=$(printf '%0360d' 0 | tr 0 a)
		R_ID=racoon2-$_pad.example; L_ID=libreswan-$_pad.example
	fi
	PSK_TXT=racoon2-libreswan-interop-0123456789abcdef
	printf '%s' "$PSK_TXT" >"$C/psk.bin"; chmod 600 "$C/psk.bin"
	CHILD_LT="ipsec_sa_lifetime_time 3600 sec;"; IKE_LT="kmp_sa_lifetime_time 3600 sec;"
	case $scen in childrekey*|pfsmismatch) CHILD_LT="ipsec_sa_lifetime_time 30 sec;" ;; esac
	[ "$scen" = ikerekey ] && IKE_LT="kmp_sa_lifetime_time 30 sec;"
	PASSIVE=on; [ "$role" = i ] && PASSIVE=off
	ESP_ENC="aes256_cbc;"; ESP_AUTH="hmac_sha2_256;"
	if [ "$scen" = frag ]; then
		ESP_ENC="aes256_cbc; aes192_cbc; aes128_cbc;"
		ESP_AUTH="hmac_sha2_256; hmac_sha2_384; hmac_sha2_512;"
	fi
	# iked's child rekey carries no KE unless PFS is configured; pin
	# pluto to the same (its default pfs=yes would answer the plain
	# rekey with NO_PROPOSAL_CHOSEN).
	# childrekeypfs: both sides want PFS on the rekey (iked need_pfs on,
	# pluto pfs=yes + an ESP DH group).  pfsmismatch: pluto's default
	# pfs=yes against iked's default off -- a realistic misconfiguration
	# whose rejection (NO_PROPOSAL_CHOSEN) iked must handle with bounded
	# backoff, not a rekey storm.
	LW_PFS=no; NEED_PFS=; LW_ESP=aes256-sha2_256
	case $scen in
	childrekeypfs) LW_PFS=yes; NEED_PFS="need_pfs on;" ;;
	pfsmismatch) LW_PFS=yes ;;
	esac

	cat >"$C/iked.conf" <<EOF
interface {
	ike { "$HR"; };
	spmd { unix "$SPMIF_R"; };
	spmd_password "$ETC/spmd.pwd";
};
resolver { resolver off; };
remote lw {
	acceptable_kmp { ikev2; };
	ikev2 {
		passive $PASSIVE;
		my_id fqdn "$R_ID";
		peers_id fqdn "$L_ID";
		peers_ipaddr "$HI";
		kmp_enc_alg { aes256_cbc; };
		kmp_prf_alg { hmac_sha2_256; };
		kmp_hash_alg { hmac_sha2_256; };
		kmp_dh_group { modp2048; };
		kmp_auth_method { psk; };
		pre_shared_key "$C/psk.bin";
		$NEED_PFS
		$IKE_LT
	};
	selector_index sel_in;
};
selector sel_out { direction outbound; src "$HR"; dst "$HI"; policy_index pol; };
selector sel_in { direction inbound; dst "$HR"; src "$HI"; policy_index pol; };
policy pol {
	action auto_ipsec;
	remote_index lw;
	ipsec_mode tunnel;
	ipsec_index { ipsec_e; };
	ipsec_level require;
	peers_sa_ipaddr "$HI";
	my_sa_ipaddr "$HR";
};
ipsec ipsec_e { $CHILD_LT sa_index esp_e; };
sa esp_e { sa_protocol esp; esp_enc_alg { $ESP_ENC }; esp_auth_alg { $ESP_AUTH }; };
EOF
	LW_AUTO=add
	cat >"$C/lw-etc/ipsec.conf" <<EOF
config setup
	logfile=$D/pluto.log
	nssdir=$C/lw-nss
	ipsecdir=$C/lw-etc
	plutodebug=none

conn r2
	type=tunnel
	ikev2=insist
	left=$HI
	leftid=@$L_ID
	leftsubnet=$HI/32
	right=$HR
	rightid=@$R_ID
	rightsubnet=$HR/32
	authby=secret
	ike=aes256-sha2_256-modp2048
	esp=$LW_ESP
	fragmentation=yes
	pfs=$LW_PFS
	ikelifetime=1h
	salifetime=1h
	rekey=no
	auto=$LW_AUTO
EOF
	printf '@%s @%s : PSK "%s"\n' "$L_ID" "$R_ID" "$PSK_TXT" >"$C/lw-etc/ipsec.secrets"
	chmod 600 "$C/lw-etc/ipsec.secrets"
	SS_CONF=$I2I_CHARON_VDIR/r2-$name.conf
	if [ "$PEER" = ss ]; then
		# Conn/child names are unique to this kind: the swanctl conf.d is
		# shared by the shard and other kinds name their child 'ch', so
		# 'swanctl --initiate --child ch' could start another kind's conn.
		# charon seat: no charon-initiated rekeys (iked drives them), no
		# PFS on the child (iked's child rekey carries no KE), RFC 7383
		# on.  Config lives in the shard's private swanctl root.
		cat >"$SS_CONF" <<EOF
connections {
	lwp {
		version = 2
		local_addrs = $HI
		remote_addrs = $HR
		proposals = aes256-sha256-modp2048
		fragmentation = yes
		rekey_time = 0
		local {
			auth = psk
			id = $L_ID
		}
		remote {
			auth = psk
			id = $R_ID
		}
		children {
			lwpch {
				local_ts = $HI/32
				remote_ts = $HR/32
				esp_proposals = aes256-sha256
				rekey_time = 0
				mode = tunnel
			}
		}
	}
}
secrets {
	ike-lwp {
		# No ids: charon fails the shared-key lookup for the
		# 370-octet FQDNs of the frag rows; the row only has one
		# peer, so a wildcard secret is exact enough.
		secret = "$PSK_TXT"
	}
}
EOF
	fi

	pkill -9 -f "$C/" 2>/dev/null || true
	rm -f "$SPMIF_R" "$SOCK_R"
	for NS in "$NSR" "$NSI"; do
		ip netns del "$NS" 2>/dev/null || true
		ip netns add "$NS"; ip netns exec "$NS" ip link set lo up
	done
	ip link add "$VR" type veth peer name "$VI"
	ip link set "$VR" netns "$NSR"; ip link set "$VI" netns "$NSI"
	ip netns exec "$NSR" ip addr add "$HR/24" dev "$VR"; ip netns exec "$NSR" ip link set "$VR" up
	ip netns exec "$NSI" ip addr add "$HI/24" dev "$VI"; ip netns exec "$NSI" ip link set "$VI" up

	# IKE bypass so UDP 500/4500 is never captured by the tunnel policy.
	for ns in "$NSR:$HR:$HI" "$NSI:$HI:$HR"; do
		NSX=${ns%%:*}; rest=${ns#*:}; LX=${rest%%:*}; PX=${rest#*:}
		for p in 500 4500; do
			ip netns exec "$NSX" ip xfrm policy add src "$PX"/32 dst "$LX"/32 proto udp sport "$p" dport "$p" dir in  ptype main action allow 2>/dev/null || true
			ip netns exec "$NSX" ip xfrm policy add src "$LX"/32 dst "$PX"/32 proto udp sport "$p" dport "$p" dir out ptype main action allow 2>/dev/null || true
		done
	done

	( ip netns exec "$NSR" python3 "$HERE/tools/ikesniff.py" "$VR" "$HR" "$D/wire.tsv" ) >"$D/sniff.out" 2>&1 &
	SNIFF=$!

	( ip netns exec "$NSR" "$SBIN/spmd" -F -f "$C/iked.conf" ) >"$D/spmd.log" 2>&1 &
	i=0; until [ -S "$SPMIF_R" ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
	( ip netns exec "$NSR" env RACOON2_ADMIN_SOCK="$SOCK_R" RACOON2_RESUME_DIR="$PRIVRES_R" \
	    "$SBIN/iked" -F -f "$C/iked.conf" -D 0x0001 -l "$D/iked.log" ) >"$D/iked.out" 2>&1 &

	if [ "$PEER" = lw ]; then
		# Same db `ipsec initnss` builds: an empty-password sql: NSS db.
		certutil -N -d "sql:$C/lw-nss" --empty-password >"$D/lw-nssinit.log" 2>&1 ||
			[ -f "$C/lw-nss/cert9.db" ] || { log "FAIL: NSS db init (certutil -N)"; lwp_cleanup; return 1; }
		( i2i_lw_ns_exec "$NSI" "$I2I_LW_PLUTO" --nofork --rundir "$C/lw-run" \
		    --ipsecdir "$C/lw-etc" --conf "$C/lw-etc/ipsec.conf" \
		    --secretsfile "$C/lw-etc/ipsec.secrets" --nssdir "$C/lw-nss" \
		    --logfile "$D/pluto.log" --stderrlog ) >"$D/pluto.out" 2>&1 &
		lwwhack() { ip netns exec "$NSI" "$I2I_LW_WHACK" --ctlsocket "$C/lw-run/pluto.ctl" "$@"; }
		i=0; until lwwhack --status >/dev/null 2>&1 || [ "$i" -ge 30 ]; do sleep 1; i=$((i+1)); done
		[ -S "$C/lw-run/pluto.ctl" ] || { log "FAIL: pluto control socket not under $C/lw-run"; lwp_cleanup; return 1; }
		# Load the conn explicitly (pluto does not parse conns from --conf
		# on every version); a duplicate add is harmless.
		ip netns exec "$NSI" "${I2I_LW_ADDCONN:-${I2I_LW_PLUTO%/*}/addconn}" --ctlsocket "$C/lw-run/pluto.ctl" \
		    --config "$C/lw-etc/ipsec.conf" r2 >"$D/addconn.log" 2>&1 || true
		# Bind pluto's IKE sockets to the (now configured) veth address.
		lwwhack --listen >"$D/whack-listen.txt" 2>&1 || true
		sleep 2

	else
		i2i_charon_run "$NSI" "$D/charon.log" || { log "FAIL: charon start"; lwp_cleanup; return 1; }
		i=0; until ip netns exec "$NSI" "$I2I_SWANCTL_BIN" --stats >/dev/null 2>&1 || [ "$i" -ge 20 ]; do sleep 1; i=$((i+1)); done
		ip netns exec "$NSI" "$I2I_SWANCTL_BIN" --load-all >"$D/swanctl-load.log" 2>&1 ||
			{ log "FAIL: swanctl --load-all"; cat "$D/swanctl-load.log"; lwp_cleanup; return 1; }
		sleep 1
	fi
	peer_initiate() {
		if [ "$PEER" = lw ]; then lwwhack --name r2 --initiate
		else ip netns exec "$NSI" "$I2I_SWANCTL_BIN" --initiate --ike lwp --child lwpch --timeout 20; fi
	}
	peer_terminate() {
		if [ "$PEER" = lw ]; then lwwhack --name r2 --terminate
		else ip netns exec "$NSI" "$I2I_SWANCTL_BIN" --terminate --ike lwp --timeout 10; fi
	}
	PEERLOG=$D/pluto.log; [ "$PEER" = ss ] && PEERLOG=$D/charon.log

	if [ "$role" = i ]; then
		# One trigger only: an ACQUIRE ping on top of establish-sa
		# would negotiate a second child pair and blur the rekey gates.
		"$SBIN/ikedctl" -s "$SOCK_R" establish-sa isakmp inet "$HR" "$HI" sel_out >/dev/null 2>&1 || true
	else
		peer_initiate >"$D/peer-init.txt" 2>&1 || true
	fi
	up=0; i=0
	while [ "$i" -lt 45 ]; do
		re=$(ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -c 'proto esp')
		le=$(ip netns exec "$NSI" ip xfrm state 2>/dev/null | grep -c 'proto esp')
		if [ "${re:-0}" -ge 2 ] && [ "${le:-0}" -ge 2 ]; then up=1; break; fi
		i=$((i+1)); sleep 1
	done
	efail=0
	[ "$up" -eq 1 ] || { log "FAIL: child not UP (iked esp=${re:-0} pluto esp=${le:-0})"; efail=1; }
	if [ "$up" -eq 1 ]; then
		ip netns exec "$NSR" ping -c3 -i0.3 -W2 "$HI" >/dev/null 2>&1 ||
			{ log "FAIL: ICMP through the tunnel"; efail=1; }
		# Sum the "N(packets)" counters under "lifetime current" for
		# iked's outbound SAs (src $HR): ICMP must have been encrypted.
		_o=$(ip netns exec "$NSR" ip -s xfrm state 2>/dev/null |
			awk -v h="src $HR dst $HI" '/^src /{o=($0==h)} o&&/lifetime current/{c=1; next} c{sub(/.*bytes\), /,""); sub(/\(packets.*/,""); n+=$0; c=0} END{print n+0}')
		[ "${_o:-0}" -ge 3 ] ||
			{ log "FAIL: outbound ESP packet counter $_o < 3 after ping"; efail=1; }
		grep -Eq 'established Child SA|CHILD_SA lwpch\{[0-9]+\} established' "$PEERLOG" 2>/dev/null ||
			{ log "FAIL: the $PEER peer never logged an established Child SA"; efail=1; }
	fi
	espspis() { ip netns exec "$NSR" ip xfrm state 2>/dev/null | awk '/proto esp spi/{print $4}' | sort | tr '\n' ' '; }
	spi0=$(espspis)
	ike0=$(awk -F'\t' '$2==35{print $4"/"$5; exit}' "$D/wire.tsv" 2>/dev/null)

	case $scen in
	frag)
		nskf=$(awk -F'\t' '$1=="out" && $2==35 && $3==53' "$D/wire.tsv" | wc -l)
		nsk=$(awk -F'\t' '$1=="out" && $2==35 && $3==46' "$D/wire.tsv" | wc -l)
		log "frag: iked IKE_AUTH SKF datagrams=$nskf unfragmented SK=$nsk"
		[ "$nskf" -ge 2 ] || { log "FAIL: no RFC 7383 fragmented IKE_AUTH from iked (SKF=$nskf)"; efail=1; }
		[ "$nsk" -eq 0 ] || { log "FAIL: iked also sent an unfragmented IKE_AUTH ($nsk)"; efail=1; }
		;;
	pfsmismatch)
		sleep 50
		nreq=$(awk -F'\t' '$1=="out" && $2==36' "$D/wire.tsv" | wc -l)
		nnp=$(grep -ac 'NO_PROPOSAL_C' "$D/iked.log")
		nbo=$(grep -ac 'rekey failed (' "$D/iked.log")
		log "pfsmismatch: CREATE_CHILD_SA requests from iked=$nreq NO_PROPOSAL_CHOSEN=$nnp backoff-armed=$nbo"
		[ "$nnp" -ge 1 ] || { log "FAIL: pluto never rejected the PFS-less rekey"; efail=1; }
		[ "$nbo" -ge 1 ] || { log "FAIL: no bounded backoff armed after the rejected rekey"; efail=1; }
		# soft at ~27 s, backoff 30 s, hard at 30 s: at most 3 attempts in
		# 50 s.  Before the backoff every soft/hard EXPIRE retried (>=4).
		[ "$nreq" -ge 1 ] && [ "$nreq" -le 3 ] ||
			{ log "FAIL: $nreq CREATE_CHILD_SA requests in 50 s (want 1..3: bounded backoff)"; efail=1; }
		;;
	childrekey|childrekeypfs|ikerekey)
		sleep 50
		n36=$(awk -F'\t' '$2==36' "$D/wire.tsv" | wc -l)
		spi1=$(espspis)
		re=$(ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -c 'proto esp')
		log "$scen: CREATE_CHILD_SA datagrams=$n36 esp before=[$spi0] after=[$spi1]"
		[ "$n36" -ge 2 ] || { log "FAIL: no CREATE_CHILD_SA exchange on the wire"; efail=1; }
		if [ "$scen" != ikerekey ]; then
			ip netns exec "$NSR" ping -c2 -i0.3 -W2 "$HI" >/dev/null 2>&1 ||
				{ log "FAIL: ICMP after rekey"; efail=1; }
			[ -n "$spi1" ] && [ "$spi1" != "$spi0" ] ||
				{ log "FAIL: ESP SPIs unchanged after child rekey"; efail=1; }
			for s in $spi0; do
				case " $spi1 " in *" $s "*) log "FAIL: old ESP SPI $s still installed"; efail=1 ;; esac
			done
			ike1=$(awk -F'\t' '{l=$4"/"$5} END{print l}' "$D/wire.tsv")
			[ "$ike1" = "$ike0" ] || { log "FAIL: child rekey changed the IKE SPIs ($ike0 -> $ike1)"; efail=1; }
		else
			# The rekey exchange itself rides the OLD SPIs; prove the
			# NEW IKE_SA is live by having pluto delete it: its
			# INFORMATIONAL must carry an IKE SPI pair other than the
			# original one, and iked must act on it.
			peer_terminate >"$D/peer-term.txt" 2>&1 || true
			sleep 5
			nnew=$(awk -F'\t' -v o="$ike0" '$1=="in" && $2==37 && $4"/"$5!=o' "$D/wire.tsv" | wc -l)
			re=$(ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -c 'proto esp')
			log "ikerekey: INFORMATIONAL on a new IKE SPI pair=$nnew (old $ike0) iked esp left=${re:-?}"
			[ "$nnew" -ge 1 ] || { log "FAIL: no message on a rekeyed IKE_SA (old $ike0)"; efail=1; }
			[ "${re:-0}" -eq 0 ] || { log "FAIL: iked kept ${re:-?} ESP SAs after DELETE on the rekeyed IKE_SA"; efail=1; }
		fi
		;;
	delete)
		peer_terminate >"$D/peer-term.txt" 2>&1 || true
		gone=0; i=0
		while [ "$i" -lt 15 ]; do
			re=$(ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -c 'proto esp')
			[ "${re:-0}" -eq 0 ] && { gone=1; break; }
			i=$((i+1)); sleep 1
		done
		n37=$(awk -F'\t' '$1=="in" && $2==37' "$D/wire.tsv" | wc -l)
		log "delete: INFORMATIONAL from peer=$n37 iked esp left=${re:-?}"
		[ "$n37" -ge 1 ] || { log "FAIL: no INFORMATIONAL DELETE from the peer on the wire"; efail=1; }
		[ "$gone" -eq 1 ] || { log "FAIL: iked kept ${re:-?} ESP SAs after the peer's DELETE"; efail=1; }
		;;
	psk) ;;
	*) log "FAIL: unknown scenario '$scen'"; efail=1 ;;
	esac
	pgrep -f -- "iked -F -f $C/iked.conf" >/dev/null 2>&1 || { log "FAIL: iked exited"; efail=1; }

	lwp_cleanup
	if [ "$efail" -ne 0 ]; then
		log "--- wire.tsv ---"; cat "$D/wire.tsv" 2>/dev/null | tail -20
		log "--- peer log ---"; tail -25 "$PEERLOG" 2>/dev/null
		log "--- iked.log ---"; grep -aiE 'error|fail|rekey|delete|frag' "$D/iked.log" 2>/dev/null | tail -15
		return 1
	fi
	log "PASS $name ($([ "$PEER" = lw ] && echo libreswan-pluto || echo strongswan-charon), $scen, iked=$([ "$role" = i ] && echo initiator || echo responder))"
	return 0
}

lwp_cleanup() {
	kill "$SNIFF" 2>/dev/null || true
	if [ "${PEER:-lw}" = ss ]; then
		i2i_charon_kill
		rm -f "$SS_CONF"
	fi
	pkill -9 -f "$C/" 2>/dev/null || true
	sleep 1
	ip netns del "$NSR" 2>/dev/null || true
	ip netns del "$NSI" 2>/dev/null || true
	rm -rf "$PRIVRES_R"
}
