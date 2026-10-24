#!/bin/sh
# kinds/i2ifeat.sh — feature rows for RFC 4739 multiple authentication,
# RFC 4478 AUTH_LIFETIME and INTERNAL_IP4_NBNS, each with its opt-in
# option ON (positive) and OFF / broken (negative), iked<->iked and against
# a strongSwan charon in both seats.  Every daemon runs in the row's own
# netns pair; no host service is touched.
#
# Row name -> scenario (seat suffix: -charon = charon initiator vs iked
# responder, -charonr = iked initiator vs charon responder, -i2i = both iked):
#   feat-mai-charonr         iked initiator: round 1 RSA signature + cert,
#                            round 2 PSK as multi_auth_second_id; charon
#                            remote + remote-2.  SA + ESP up.
#   feat-mai-nosup-charonr   charon multiple_authentication = no: iked must
#                            refuse (policy needs both rounds), no SA.
#   feat-mai-badpsk-charonr  round-2 PSK wrong at charon: no SA, no ESP.
#   feat-mai-off-charonr     multiple_auth off (second id still set): iked
#                            sends neither MULTIPLE_AUTH_SUPPORTED nor
#                            ANOTHER_AUTH_FOLLOWS; charon's remote-2 is
#                            unmet, no SA.
#   feat-mai-i2i             iked initiator two rounds vs an iked responder
#                            (its second round is EAP only): refused, no SA.
#   feat-al-i2i              responder auth_lifetime 30, initiator
#                            honor_auth_lifetime on: cap logged <=30 s and
#                            a fresh IKE_SA_INIT (full reauth) measured
#                            20..60 s after the first.
#   feat-al-nohonor-i2i      same, honor off: no cap, no second IKE_SA_INIT
#                            within 60 s.
#   feat-al-charon           charon initiator vs iked auth_lifetime 30:
#                            charon schedules reauth and reauthenticates.
#   feat-al-off-charon       iked responder without auth_lifetime: charon
#                            receives no AUTH_LIFETIME.
#   feat-al-charonr          charon responder reauth_time 30s: strongSwan
#                            sends no AUTH_LIFETIME as responder, it
#                            reauthenticates itself; iked (honor on) caps
#                            nothing and answers the fresh IKE_SA.
#   feat-nbns-i2i            request + provide nbns: server received.
#   feat-nbns-off-i2i        initiator requests ip4_nbns, responder has no
#                            nbns: none received, SA up.
#   feat-nbns-charonr        iked initiator requests ip4_nbns + an address (ip4)
#                            from a charon pool with attr nbns.
FEAT_PSK2_HEX=7365636f6e642d726f756e642d70736b		# "second-round-psk"

feat_ts() {	# feat_ts <log> <ERE> <nth> -> epoch seconds of the nth match
	_l=$(grep -E -- "$2" "$1" 2>/dev/null | sed -n "${3}p")
	[ -n "$_l" ] || return 1
	case $_l in
	20[0-9][0-9]-*) date -d "$(printf '%s' "$_l" | cut -c1-19)" +%s ;;
	*) _t=$(printf '%s' "$_l" | cut -c1-8); date -d "today $_t" +%s ;;
	esac
}

feat_iked_conf() {	# feat_iked_conf <file> <role i|r> <extra-ikev2-lines> <auth-lines> <cfg-lines>
	_f=$1 _role=$2
	if [ "$_role" = r ]; then
		_me=$HR _peer=$HI _myid=racoon2-matrix _pid=r2init-matrix _pas=on _spm=$SPMIF_R _rm=matrix_resp
	else
		_me=$HI _peer=$HR _myid=r2init-matrix _pid=racoon2-matrix _pas=off _spm=$SPMIF_I _rm=matrix_init
	fi
	cat > "$_f" <<EOF
interface {
	ike { "$_me"; };
	spmd { unix "$_spm"; };
	spmd_password "$ETC/spmd.pwd";
};
resolver { resolver off; };
remote $_rm {
	acceptable_kmp { ikev2; };
	ikev2 {
		passive $_pas;
		my_id fqdn "$_myid";
		peers_id fqdn "$_pid";
		peers_ipaddr "$_peer";
		kmp_enc_alg { aes_gcm; };
		kmp_prf_alg { hmac_sha2_256; };
		kmp_hash_alg { hmac_sha2_256; };
		kmp_dh_group { ecp256; };
$4
$3
$5
		dpd_delay 60 sec;
	};
	selector_index sel_in;
};
selector sel_out {
	direction outbound;
	src "$_me"; dst "$_peer";
	policy_index pol;
};
selector sel_in {
	direction inbound;
	dst "$_me"; src "$_peer";
	policy_index pol;
};
policy pol {
	action auto_ipsec;
	remote_index $_rm;
	ipsec_mode tunnel;
	ipsec_index { ipsec_e; };
	ipsec_level require;
	peers_sa_ipaddr "$_peer";
	my_sa_ipaddr "$_me";
};
ipsec ipsec_e {
	sa_index esp_e;
};
sa esp_e {
	sa_protocol esp;
	esp_enc_alg { aes_gcm; };
	esp_auth_alg { non_auth; };
};
EOF
}

feat_start_iked() {	# feat_start_iked <r|i>
	if [ "$1" = r ]; then _ns=$NSR _spm=$SPMIF_R _so=$SOCK_R _pr=$PRIVRES_R _cf=$C/responder.conf _lg=$D/resp
	else _ns=$NSI _spm=$SPMIF_I _so=$SOCK_I _pr=$PRIVRES_I _cf=$C/initiator.conf _lg=$D/init; fi
	( ip netns exec "$_ns" "$SBIN/spmd" -F -f "$_cf" ) >"$_lg-spmd.log" 2>&1 &
	i=0; until [ -S "$_spm" ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
	( ip netns exec "$_ns" env RACOON2_ADMIN_SOCK="$_so" RACOON2_RESUME_DIR="$_pr" \
	    "$SBIN/iked" -F -f "$_cf" -D 0x0003 -l "$_lg-iked.log" ) >"$_lg-iked.out" 2>&1 &
}

feat_charon_conf() {	# feat_charon_conf <role i|r> <local+remote blocks> <conn-extra> <secrets>
	mkdir -p "$I2I_CHARON_VDIR" || return 1
	rm -f "$I2I_CHARON_VDIR"/*.conf 2>/dev/null || true
	if [ "$1" = r ]; then _la=$HR _ra=$HI _lt=$HR _rt=$HI; else _la=$HI _ra=$HR _lt=$HI _rt=$HR; fi
	cat > "$I2I_CHARON_VDIR/r2-$name.conf" <<EOF
connections {
	r2feat {
		version = 2
		proposals = $FEAT_PROPOSALS
		local_addrs = $_la
		remote_addrs = $_ra
		rekey_time = 0s
$3
$2
		children {
			ch {
				local_ts = ${FEAT_LTS:-$_lt/32}
				remote_ts = $_rt/32
				esp_proposals = aes128gcm16
				rekey_time = 0s
			}
		}
	}
}
${FEAT_POOLS:-}
secrets {
$4
}
EOF
}

feat_charon_mlkem() {	# runtime proof: does this strongSwan list ML_KEM_768?
	# (a string scan is not proof: Debian 6.0.1 names ML_KEM_768 in its
	# enum tables yet refuses it).  Probed once per run in a scratch netns.
	if [ -z "${FEAT_MLKEM:-}" ]; then
		_pn=r2mlk$$ _pl=/tmp/r2-mlkem-probe-$$.log
		ip netns add "$_pn" && ip netns exec "$_pn" ip link set lo up
		i2i_charon_run "$_pn" "$_pl"
		FEAT_MLKEM=no; _k=0
		while [ "$_k" -lt 10 ]; do
			if _al=$(ip netns exec "$_pn" "$I2I_SWANCTL_BIN" --list-algs 2>/dev/null) && [ -n "$_al" ]; then
				printf '%s\n' "$_al" | grep -q 'ML_KEM_768' && FEAT_MLKEM=yes; break
			fi
			sleep 1; _k=$((_k+1))
		done
		i2i_charon_kill; ip netns del "$_pn" 2>/dev/null || true
		log "charon ML-KEM-768 (swanctl --list-algs): $FEAT_MLKEM"
	fi
	[ "$FEAT_MLKEM" = yes ]
}

kind_i2ifeat() {	# restores SBIN/ETC if a row switched to the classical build
	_fs=$SBIN _fe=$ETC
	feat_row "$@"; _fr=$?
	SBIN=$_fs ETC=$_fe
	return "$_fr"
}

feat_row() {
	name=$1
	require_root || return 1
	[ -x "$SBIN/iked" ] || { log "FAIL: no $SBIN/iked"; return 1; }
	[ -f "$ETC/psk/macos.psk" ] || { log "FAIL: no $ETC/psk/macos.psk"; return 1; }
	row_ns "$name"
	HR=192.0.7.1; HI=192.0.7.2
	PEER=iked; PEER_R=iked
	case $name in *-charonr) PEER_R=charon ;; *-charon) PEER=charon ;; esac
	if [ "$PEER" = charon ] || [ "$PEER_R" = charon ]; then
		command -v "$I2I_CHARON_BIN" >/dev/null 2>&1 || { log "FAIL: no charon $I2I_CHARON_BIN"; return 1; }
	fi
	# An ADDKE build of iked offers a mandatory ML-KEM-768 type-6 in its
	# initial IKE_SA; a charon seat must then negotiate it (ke1_mlkem768,
	# needs ML-KEM in strongSwan).  A classical iked build pairs with a
	# classical proposal.  Print which pairing the row runs.
	# Only an iked INITIATOR imposes it: an iked responder answers a
	# classical charon offer on either build.
	FEAT_PROPOSALS=aes256gcm16-prfsha256-ecp256
	# ADDKE iked initiator + a charon without ML-KEM: switch to the
	# classical build named by R2_CLASSIC_PREFIX when there is one (the
	# box), else the row FAILs below with the proof.
	if [ "$PEER_R" = charon ] && grep -aq 'ikesa-addke offer' "$SBIN/iked" 2>/dev/null &&
	    ! feat_charon_mlkem && [ -n "${R2_CLASSIC_PREFIX:-}" ] && [ -x "$R2_CLASSIC_PREFIX/sbin/iked" ] &&
	    ! grep -aq 'ikesa-addke offer' "$R2_CLASSIC_PREFIX/sbin/iked"; then
		log "charon has no ML-KEM: using the classical iked build $R2_CLASSIC_PREFIX"
		SBIN=$R2_CLASSIC_PREFIX/sbin ETC=$R2_CLASSIC_PREFIX/etc/racoon2
	fi
	if [ "$PEER_R" = charon ] && grep -aq 'ikesa-addke offer' "$SBIN/iked" 2>/dev/null; then
		FEAT_PROPOSALS=aes256gcm16-prfsha256-ecp256-ke1_mlkem768
		log "iked ADDKE build: charon responder must do ML-KEM-768 (ke1_mlkem768)"
	fi
	log "charon IKE proposal: $FEAT_PROPOSALS"
	pkill -9 -f "$C/" 2>/dev/null || true
	i2i_charon_kill
	rm -rf "$PRIVRES_R" "$PRIVRES_I" "$D" "$C"; mkdir -p "$PRIVRES_R" "$PRIVRES_I" "$D" "$C"
	rm -f "$SPMIF_R" "$SPMIF_I" "$SOCK_R" "$SOCK_I"
	PSKHEX=$(psk_file_hex "$ETC/psk/macos.psk") || { log "FAIL: psk hex"; return 1; }
	PSK_I="		kmp_auth_method { psk; };
		pre_shared_key \"$ETC/psk/macos.psk\";"
	I_EXTRA= R_EXTRA= I_CFG= R_CFG= I2I_CHARON_EXTRA= I2I_CHARON_PLUGINS_EXTRA= FEAT_POOLS= FEAT_LTS=
	CH_AUTH="		local {
			auth = psk
			id = $( [ "$PEER" = charon ] && echo r2init-matrix || echo racoon2-matrix )
		}
		remote {
			auth = psk
			id = $( [ "$PEER" = charon ] && echo racoon2-matrix || echo r2init-matrix )
		}"
	CH_SEC="	ike-a {
		secret = 0x$PSKHEX
	}"
	CH_CONN=
	AUTH_I=$PSK_I AUTH_R=$PSK_I
	case $name in
	feat-mai-*)
		openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=r2init-matrix" \
		    -addext "subjectAltName=DNS:r2init-matrix" -keyout "$C/key-i.pem" -out "$C/cert-i.pem" >/dev/null 2>&1 &&
		openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=racoon2-matrix" \
		    -addext "subjectAltName=DNS:racoon2-matrix" -keyout "$C/key-r.pem" -out "$C/cert-r.pem" >/dev/null 2>&1 &&
		openssl x509 -in "$C/cert-i.pem" -pubkey -noout > "$C/pub-i.pem" 2>/dev/null ||
		    { log "FAIL: openssl certs"; return 1; }
		chmod 644 "$C"/*.pem
		# second-round PSK: its own file, distinct from the default one
		printf 'second-round-psk' > "$C/psk2"; chmod 600 "$C/psk2"
		AUTH_I="		kmp_auth_method { rsasig; };
		my_public_key x509pem \"$C/cert-i.pem\" \"$C/key-i.pem\";
		peers_public_key x509pem \"$C/cert-r.pem\";
		pre_shared_key \"$C/psk2\";"
		AUTH_R="		kmp_auth_method { rsasig; };
		my_public_key x509pem \"$C/cert-r.pem\" \"$C/key-r.pem\";
		peers_public_key x509pem \"$C/cert-i.pem\";
		pre_shared_key \"$C/psk2\";"
		case $name in
		*-off-*) I_EXTRA='		multiple_auth off;
		multi_auth_second_id fqdn "r2second";' ;;
		*)       I_EXTRA='		multiple_auth on;
		multi_auth_second_id fqdn "r2second";' ;;
		esac
		R_EXTRA='		multiple_auth on;'
		mkdir -p "${I2I_CHARON_VDIR%/conf.d}/private"
		cp "$C/key-r.pem" "${I2I_CHARON_VDIR%/conf.d}/private/r2-$name-key-r.pem"
		CH_AUTH="		local {
			auth = pubkey
			id = racoon2-matrix
			certs = $C/cert-r.pem
		}
		remote {
			auth = pubkey
			id = r2init-matrix
			pubkeys = $C/pub-i.pem
		}
		remote-2 {
			auth = psk
			id = r2second
		}"
		_s2=$FEAT_PSK2_HEX
		case $name in *-badpsk-*) _s2=77726f6e672d726f756e642d70736b21 ;; esac
		CH_SEC="	ike-2 {
		id = r2second
		secret = 0x$_s2
	}"
		case $name in *-nosup-*) I2I_CHARON_EXTRA='	multiple_authentication = no' ;; esac
		;;
	feat-al-*)
		case $name in
		*-off-*) ;;
		*) R_EXTRA='		auth_lifetime 30 sec;' ;;
		esac
		case $name in
		*-nohonor-*) I_EXTRA='		honor_auth_lifetime off;' ;;
		*)           I_EXTRA='		honor_auth_lifetime on;' ;;
		esac
		[ "$PEER_R" = charon ] && CH_CONN='		reauth_time = 30s
		over_time = 10s'
		;;
	feat-nbns-*)
		I_CFG='		request { ip4_nbns; };'
		[ "$name" = feat-nbns-i2i ] && R_CFG='		provide { nbns "192.0.2.137"; };'
		if [ "$PEER_R" = charon ]; then
			I_CFG='		request { ip4; ip4_nbns; };'
			I2I_CHARON_PLUGINS_EXTRA='		attr {
			nbns = 192.0.2.138
		}'
			FEAT_POOLS="pools {
	p4 {
		addrs = 10.77.0.0/28
	}
}"
			CH_CONN='		pools = p4'
			FEAT_LTS=0.0.0.0/0
		fi
		;;
	esac

	[ "$PEER" = iked ] && feat_iked_conf "$C/initiator.conf" i "$I_EXTRA" "$AUTH_I" "$I_CFG"
	[ "$PEER_R" = iked ] && feat_iked_conf "$C/responder.conf" r "$R_EXTRA" "$AUTH_R" "$R_CFG"
	if [ "$PEER" = charon ]; then feat_charon_conf i "$CH_AUTH" "$CH_CONN" "$CH_SEC" || return 1; fi
	if [ "$PEER_R" = charon ]; then feat_charon_conf r "$CH_AUTH" "$CH_CONN" "$CH_SEC" || return 1; fi

	for NS in "$NSR" "$NSI"; do
		ip netns del "$NS" 2>/dev/null || true
		ip netns add "$NS"; ip netns exec "$NS" ip link set lo up
	done
	ip link add "$VR" type veth peer name "$VI"
	ip link set "$VR" netns "$NSR"; ip netns exec "$NSR" ip link set "$VR" up
	ip netns exec "$NSR" ip addr add "$HR/24" dev "$VR"
	ip link set "$VI" netns "$NSI"; ip netns exec "$NSI" ip link set "$VI" up
	ip netns exec "$NSI" ip addr add "$HI/24" dev "$VI"
	for ns in "$NSR:$HR:$HI" "$NSI:$HI:$HR"; do
		NSX=${ns%%:*}; rest=${ns#*:}; LX=${rest%%:*}; PX=${rest#*:}
		for p in 500 4500; do
			ip netns exec "$NSX" ip xfrm policy add src "$PX"/32 dst "$LX"/32 proto udp sport "$p" dport "$p" dir in  ptype main action allow 2>/dev/null || true
			ip netns exec "$NSX" ip xfrm policy add src "$LX"/32 dst "$PX"/32 proto udp sport "$p" dport "$p" dir out ptype main action allow 2>/dev/null || true
		done
	done

	T0=$(date +%s)
	if [ "$PEER_R" = charon ]; then
		i2i_charon_run "$NSR" "$D/charon-resp.log"; sleep 2
		ip netns exec "$NSR" "$I2I_SWANCTL_BIN" --load-all --debug 2 >"$D/swanctl-load.log" 2>&1
	else
		feat_start_iked r
	fi
	if [ "$PEER" = charon ]; then
		i2i_charon_run "$NSI" "$D/charon-init.log"; sleep 2
		ip netns exec "$NSI" "$I2I_SWANCTL_BIN" --load-all --debug 2 >"$D/swanctl-load.log" 2>&1
		ip netns exec "$NSI" "$I2I_SWANCTL_BIN" --initiate --child ch --timeout 20 >"$D/swanctl-init.log" 2>&1 || true
	else
		feat_start_iked i
		sleep 2
		"$SBIN/ikedctl" -s "$SOCK_I" establish-sa isakmp inet "$HI" "$HR" sel_out >/dev/null 2>&1 || true
	fi

	# ESP up?  negative rows wait the full window to prove nothing lands
	up=0; i=0
	while [ "$i" -lt 20 ]; do
		re=$(ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -c 'proto esp')
		ie=$(ip netns exec "$NSI" ip xfrm state 2>/dev/null | grep -c 'proto esp')
		if [ "${re:-0}" -ge 2 ] && [ "${ie:-0}" -ge 2 ]; then up=1; break; fi
		i=$((i+1)); sleep 1
	done
	log "ESP: resp=$re init=$ie up=$up after ${i}s"
	IL=$D/init-iked.log RL=$D/resp-iked.log CI=$D/charon-init.log CR=$D/charon-resp.log
	efail=0
	want_up=1
	case $name in feat-mai-nosup-*|feat-mai-badpsk-*|feat-mai-off-*|feat-mai-i2i) want_up=0 ;; esac
	if [ "$want_up" = 1 ]; then
		[ "$up" = 1 ] || { log "FAIL: SA/ESP not up"; efail=1; }
		[ "$up" = 1 ] && i2i_dataplane "$NSI" "$HR" "$name"
	else
		[ "$up" = 0 ] && [ "${re:-0}" = 0 ] && [ "${ie:-0}" = 0 ] ||
		    { log "FAIL: an ESP SA landed on a row that must refuse (resp=$re init=$ie)"; efail=1; }
	fi
	need() {	# need <file> <ERE> <what>
		if grep -qE -- "$2" "$1" 2>/dev/null; then log "GATE ok: $3"
		else log "FAIL: $3 (/$2/ not in ${1##*/})"; efail=1; fi
	}
	never() {	# never <file> <ERE> <what>
		if grep -qE -- "$2" "$1" 2>/dev/null; then
			log "FAIL: $3 ($(grep -E -- "$2" "$1" | head -1))"; efail=1
		else log "GATE ok: $3"; fi
	}

	case $name in
	feat-mai-charonr)
		need "$IL" 'multiple auth: first round, ANOTHER_AUTH_FOLLOWS' "iked flagged round one"
		need "$IL" 'multiple auth: responder verified, second round \(PSK\) sent' "iked sent round two"
		need "$CR" 'parsed IKE_AUTH request 1 .*N\(AUTH_FOLLOWS\)' "charon saw ANOTHER_AUTH_FOLLOWS"
		need "$CR" "authentication of 'r2init-matrix' with RSA" "charon verified round one (RSA)"
		need "$CR" "authentication of 'r2second' with pre-shared key successful" "charon verified round two (PSK)"
		need "$CR" 'IKE_SA r2feat\[[0-9]+\] established' "charon ESTABLISHED"
		;;
	feat-mai-nosup-charonr)
		never "$CR" 'MULT_AUTH' "charon did not advertise MULTIPLE_AUTH_SUPPORTED"
		need "$IL" 'did not send MULTIPLE_AUTH_SUPPORTED; aborting' "iked refused the single-round fallback"
		never "$CR" 'parsed IKE_AUTH request' "no IKE_AUTH reached charon"
		;;
	feat-mai-badpsk-charonr)
		need "$IL" 'second round \(PSK\) sent' "iked ran round two"
		need "$CR" "authentication of 'r2second' with pre-shared key failed|tried [0-9]+ shared key" "charon rejected the round-two PSK"
		need "$CR" 'generating IKE_AUTH response 2 \[ N\(AUTH_FAILED\) \]' "charon answered AUTHENTICATION_FAILED"
		never "$IL" 'ESTABLISHED' "iked never ESTABLISHED"
		;;
	feat-mai-off-charonr)
		never "$CR" 'parsed IKE_AUTH request 1 .*N\((MULT_AUTH|AUTH_FOLLOWS)\)' "iked sent no RFC 4739 notify while off"
		never "$IL" 'multiple auth:' "iked ran no multi-auth round while off"
		never "$CR" 'IKE_SA r2feat\[[0-9]+\] established' "charon did not establish (remote-2 unmet)"
		;;
	feat-mai-i2i)
		need "$RL" 'advertising MULTIPLE_AUTH_SUPPORTED' "responder advertised"
		need "$IL" 'multiple auth: first round, ANOTHER_AUTH_FOLLOWS' "initiator flagged round one"
		need "$RL" 'AUTHENTICATION_FAILED|authentication fail|multiple auth.*(refus|no EAP)' "responder refused a non-EAP second round"
		never "$IL" 'ESTABLISHED' "initiator never ESTABLISHED"
		;;
	feat-al-charonr)
		# strongSwan as RESPONDER with reauth_time never sends
		# AUTH_LIFETIME: it reauthenticates itself (becomes initiator of
		# a fresh IKE_SA).  Prove that, that iked honours nothing it was
		# not sent, and that iked answers charon's reauthentication.
		never "$CR" 'generating IKE_AUTH response 1 .*N\(AUTH_LFT\)' "charon responder sent no AUTH_LIFETIME"
		k=0; while [ "$k" -lt 40 ]; do
			grep -q 'reauthenticating IKE_SA' "$CR" 2>/dev/null && break
			ip netns exec "$NSI" ping -c1 -W1 "$HR" >/dev/null 2>&1; sleep 1; k=$((k+1))
		done
		need "$CR" 'reauthenticating IKE_SA' "charon reauthenticated itself (reauth_time 30s)"
		sleep 5
		need "$IL" 'RES_IKE_AUTH_RCVD -> ESTABLISHED' "iked accepted charon's fresh IKE_SA as responder"
		never "$IL" 'AUTH_LIFETIME: IKE SA lifetime capped' "iked capped nothing"
		;;
	feat-al-i2i|feat-al-nohonor-i2i)
		LOGP=$CR; [ "$PEER_R" = iked ] && LOGP=$RL
		if [ "$PEER_R" = iked ]; then need "$RL" 'sending AUTH_LIFETIME 30' "responder sent AUTH_LIFETIME 30"
		else need "$CR" 'generating IKE_AUTH response 1 .*N\(AUTH_LFT\)' "charon sent AUTH_LIFETIME"; fi
		# measure: keep traffic flowing 70 s; count fresh IKE_SA_INIT
		# initiations by the iked initiator
		k=0; while [ "$k" -lt 35 ]; do
			ip netns exec "$NSI" ping -c1 -W1 "$HR" >/dev/null 2>&1; sleep 1; k=$((k+1))
			[ "$(grep -c 'IDLING -> INI_IKE_SA_INIT_SENT' "$IL" 2>/dev/null)" -ge 2 ] && [ "$k" -ge 5 ] && break
		done
		n=$(grep -c 'IDLING -> INI_IKE_SA_INIT_SENT' "$IL" 2>/dev/null)
		t1=$(feat_ts "$IL" 'IDLING -> INI_IKE_SA_INIT_SENT' 1); t2=$(feat_ts "$IL" 'IDLING -> INI_IKE_SA_INIT_SENT' 2)
		log "measured: IKE_SA_INIT initiations=$n first=${t1:-?} second=${t2:-?}"
		if [ "$name" = feat-al-nohonor-i2i ]; then
			never "$IL" 'AUTH_LIFETIME: IKE SA lifetime capped' "honor off: no cap"
			[ "$n" -eq 1 ] && log "GATE ok: honor off: one IKE_SA_INIT in 35 s" ||
			    { log "FAIL: honor off but $n IKE_SA_INIT initiations"; efail=1; }
		else
			cap=$(grep -oE 'AUTH_LIFETIME: IKE SA lifetime capped to [0-9]+s' "$IL" | head -1 | grep -oE '[0-9]+s$' | tr -d s)
			if [ -n "$cap" ] && [ "$cap" -ge 15 ] && [ "$cap" -le 30 ]; then log "GATE ok: cap ${cap}s (<=30)"
			else log "FAIL: no AUTH_LIFETIME cap in 15..30 s (got '${cap:-none}')"; efail=1; fi
			if [ -n "$t2" ] && [ $((t2 - t1)) -ge 10 ] && [ $((t2 - t1)) -le 34 ]; then
				log "GATE ok: reauth (fresh IKE_SA_INIT) $((t2 - t1)) s after the first"
			else log "FAIL: no fresh IKE_SA_INIT 10..34 s after the first (n=$n)"; efail=1; fi
			k=0; while [ "$k" -lt 15 ]; do
				[ "$(grep -c 'INI_IKE_AUTH_RCVD -> ESTABLISHED' "$IL")" -ge 2 ] && break; sleep 1; k=$((k+1))
			done
			ne=$(grep -c 'INI_IKE_AUTH_RCVD -> ESTABLISHED' "$IL")
			ie=$(ip netns exec "$NSI" ip xfrm state 2>/dev/null | grep -c 'proto esp')
			if [ "$ne" -ge 2 ] && [ "${ie:-0}" -ge 2 ] && ip netns exec "$NSI" ping -c2 -W2 "$HR" >/dev/null 2>&1; then
				log "GATE ok: reauthenticated SA ESTABLISHED ($ne full IKE_AUTHs), ESP $ie, ping ok"
			else log "FAIL: reauthenticated SA not up (IKE_AUTH established=$ne esp=$ie)"; efail=1; fi
		fi
		;;
	feat-al-charon|feat-al-off-charon)
		if [ "$name" = feat-al-off-charon ]; then
			never "$CI" 'received AUTH_LIFETIME' "no AUTH_LIFETIME while auth_lifetime unset"
			never "$RL" 'sending AUTH_LIFETIME' "iked sent none"
		else
			need "$CI" 'received AUTH_LIFETIME of 30s, scheduling reauthentication in [0-9]+s' "charon scheduled reauth from AUTH_LIFETIME 30"
			k=0; while [ "$k" -lt 40 ]; do
				grep -qE 'reauthenticating IKE_SA' "$CI" 2>/dev/null && break; sleep 1; k=$((k+1))
			done
			t1=$(feat_ts "$CI" 'received AUTH_LIFETIME' 1); t2=$(feat_ts "$CI" 'reauthenticating IKE_SA' 1)
			if [ -n "$t2" ] && [ $((t2 - t1)) -le 31 ]; then
				log "GATE ok: charon reauthenticated $((t2 - t1)) s after AUTH_LIFETIME 30"
			else log "FAIL: charon did not reauthenticate within 31 s"; efail=1; fi
		fi
		;;
	feat-nbns-i2i)
		need "$IL" 'INTERNAL_IP4_NBNS: 192.0.2.137' "initiator received the configured NBNS server"
		;;
	feat-nbns-off-i2i)
		need "$IL" 'INTERNAL_IP4_NBNS' "initiator put INTERNAL_IP4_NBNS in CFG_REQUEST" 
		never "$IL" 'INTERNAL_IP4_NBNS: ' "no NBNS server received (responder has none)"
		;;
	feat-nbns-charonr)
		need "$IL" 'INTERNAL_IP4_NBNS: 192.0.2.138' "iked received charon's NBNS server"
		;;
	esac
	if grep -q 'key exchange method ML_KEM_768 not supported' "$CR" 2>/dev/null; then
		log "FAIL: this strongSwan has no ML-KEM-768 but the ADDKE iked initiator offers it as mandatory; run -charonr rows against an ML-KEM strongSwan or a classical iked build"
		efail=1
	fi
	if [ "$PEER" = charon ] || [ "$PEER_R" = charon ]; then i2i_charon_kill; fi
	pkill -9 -f "$C/" 2>/dev/null || true
	[ "$efail" -eq 0 ] && log "PASS $name"
	return "$efail"
}
