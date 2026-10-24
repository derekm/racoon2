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
#   feat-mai-i2i             iked<->iked two rounds: RSA, then PSK as
#                            r2second verified by the responder's
#                            multi_auth_second_id.  SA + ESP up.
#   feat-mai-badpsk-i2i      responder holds a different round-2 PSK:
#                            round two rejected, no SA.
#   feat-mai-nosup-i2i       responder multiple_auth off: no
#                            MULTIPLE_AUTH_SUPPORTED, initiator refuses.
#   feat-mai-charon          charon initiator (local + local-2 psk) vs the
#                            iked responder's PSK second round.  SA up.
#   feat-mai-nopeer-charon   charon multiple_authentication = no: no
#                            MULTIPLE_AUTH_SUPPORTED, one round only; the
#                            iked responder requires its second identity
#                            and refuses.  No SA.  (The flag-without-
#                            support case is pinned by notifytest: no
#                            stock peer sends it.)
#   feat-al-i2i              responder auth_lifetime 30, initiator
#                            honor_auth_lifetime on: cap logged in 15..30 s
#                            and a fresh IKE_SA_INIT (full reauth) measured
#                            10..34 s after the first; the new SA reaches
#                            ESTABLISHED with ESP and ping.
#   feat-al-nohonor-i2i      same, honor off: no cap, exactly one
#                            IKE_SA_INIT in the 35 s window.
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
# blocklistd rows (gate blocklist: an --enable-blocklist iked).  The
# responder's iked runs in a mount namespace with a private tmpfs on /run
# and a sink bound to libblocklist's socket path, so every report is
# counted and parsed and no real blocklistd / firewall is ever touched:
#   feat-bl-off-i2i          bad PSK, blocklist unset: no report.
#   feat-bl-on-i2i           bad PSK, blocklist on: one AUTH_FAIL (BL_ADD)
#                            for the initiator's address, no SA.
#   feat-bl-ok-i2i           good PSK, blocklist on: AUTH_OK (BL_DELETE), SA up.
#   feat-bl-logonly-i2i      bad PSK, on + log_only: logged, nothing sent.
#   feat-bl-prehs-off-i2i    short junk datagram, prehandshake unset: not
#                            reported (unverified source).
#   feat-bl-prehs-on-i2i     same, prehandshake on: reported.
#   feat-bl-on-charon        charon initiator, wrong PSK: reported.
#   feat-bl-init-charonr     iked INITIATOR, blocklist on, charon answers
#                            with a wrong-PSK AUTH: no report (initiator
#                            side never reports a peer it dialled).
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
$( [ "$_role" = "${BL_ROLE:-r}" ] && printf '%s' "${BL_IF:-}" )
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

feat_bl_sink() {	# feat_bl_sink <sock> <log>: count libblocklist datagrams
	cat > "$C/blsink.py" <<'EOF'
import os, socket, struct, sys
path, log = sys.argv[1], sys.argv[2]
os.makedirs(os.path.dirname(path), exist_ok=True)
try: os.unlink(path)
except OSError: pass
s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
s.bind(path); os.chmod(path, 0o666)
with open(log, "a", buffering=1) as f:
    f.write("SINK ready %s\n" % path)
    while True:
        d, anc, _, _ = s.recvmsg(4096, 256)
        fds = sum(1 for l, t, _ in anc if l == socket.SOL_SOCKET and t == socket.SCM_RIGHTS)
        if len(d) < 16 + 128:
            f.write("BL short %d\n" % len(d)); continue
        ln, ver, typ, salen = struct.unpack_from("=IIII", d, 0)
        fam = struct.unpack_from("=H", d, 16)[0]
        addr = socket.inet_ntop(socket.AF_INET, d[20:24]) if fam == socket.AF_INET else \
            socket.inet_ntop(socket.AF_INET6, d[24:40]) if fam == socket.AF_INET6 else "?"
        why = d[144:ln].split(b"\0")[0].decode("ascii", "replace")
        f.write("BL type=%d af=%d addr=%s fds=%d why=%s\n" % (typ, fam, addr, fds, why))
EOF
}

feat_start_iked() {	# feat_start_iked <r|i>
	if [ "$1" = r ]; then _ns=$NSR _spm=$SPMIF_R _so=$SOCK_R _pr=$PRIVRES_R _cf=$C/responder.conf _lg=$D/resp
	else _ns=$NSI _spm=$SPMIF_I _so=$SOCK_I _pr=$PRIVRES_I _cf=$C/initiator.conf _lg=$D/init; fi
	( ip netns exec "$_ns" "$SBIN/spmd" -F -f "$_cf" ) >"$_lg-spmd.log" 2>&1 &
	i=0; until [ -S "$_spm" ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
	if [ "$1" = "${BL_ROLE:-r}" ] && [ -n "${FEAT_BLSOCK:-}" ]; then
		# private /run (ip netns exec already gave a slave mount ns):
		# the sink owns libblocklist's socket path only in here
		( ip netns exec "$_ns" sh -c 'mount -t tmpfs r2bl "$(readlink -f "$(dirname "$1")" | cut -d/ -f1-2)" &&
		    { python3 "$2/blsink.py" "$1" "$3" & } &&
		    i=0; until grep -q "SINK ready" "$3" 2>/dev/null || [ "$i" -ge 50 ]; do sleep 0.1; i=$((i+1)); done;
		    exec env RACOON2_ADMIN_SOCK="$4" RACOON2_RESUME_DIR="$5" "$6" -F -f "$7" -D 0x0003 -l "$8"' \
		    feat "$FEAT_BLSOCK" "$C" "$D/blsink.log" "$_so" "$_pr" "$SBIN/iked" "$_cf" "$_lg-iked.log" ) >"$_lg-iked.out" 2>&1 &
		return
	fi
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

# every gate also lands as a structured "GATE <row> <label> PASS|FAIL"
# line, which run.sh counts into the results TSV (gates_pass/gates_fail)
feat_ok() { log "GATE ok: $1"; r2_gate "g$((_fg=${_fg:-0}+1))" PASS "$1"; }
feat_bad() { log "FAIL: $1"; r2_gate "g$((_fg=${_fg:-0}+1))" FAIL "$1"; efail=1; }

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
	FEAT_BLSOCK= BL_IF= BL_ROLE=r
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
		# iked responder: a PSK second round for r2second (RFC 4739 s3.2)
		case $name in
		feat-mai-i2i|feat-mai-badpsk-i2i|feat-mai-charon|feat-mai-nopeer-charon)
			R_EXTRA='		multiple_auth on;
		multi_auth_second_id fqdn "r2second";' ;;
		feat-mai-nosup-i2i) R_EXTRA='		multiple_auth off;' ;;
		esac
		if [ "$name" = feat-mai-badpsk-i2i ]; then
			printf 'wrong-round-psk!' > "$C/psk2-r"; chmod 600 "$C/psk2-r"
			AUTH_R=$(printf '%s' "$AUTH_R" | sed "s|$C/psk2|$C/psk2-r|")
		fi
		mkdir -p "${I2I_CHARON_VDIR%/conf.d}/private"
		cp "$C/key-r.pem" "${I2I_CHARON_VDIR%/conf.d}/private/r2-$name-key-r.pem"
		cp "$C/key-i.pem" "${I2I_CHARON_VDIR%/conf.d}/private/r2-$name-key-i.pem"
		openssl x509 -in "$C/cert-r.pem" -pubkey -noout > "$C/pub-r.pem" 2>/dev/null
		chmod 644 "$C"/*.pem
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
		case $name in *-nosup-*|feat-mai-nopeer-charon) I2I_CHARON_EXTRA='	multiple_authentication = no' ;; esac
		if [ "$PEER" = charon ]; then
			# charon initiator: round 1 RSA (cert-i), round 2 PSK as r2second
			CH_AUTH="		local {
			auth = pubkey
			id = r2init-matrix
			certs = $C/cert-i.pem
		}
		local-2 {
			auth = psk
			id = r2second
		}
		remote {
			auth = pubkey
			id = racoon2-matrix
			pubkeys = $C/pub-r.pem
		}"
		fi
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

	case $name in
	feat-bl-*)
		grep -aq 'blocklist: reported' "$SBIN/iked" ||
		    { log "FAIL: $SBIN/iked has no blocklist support (--enable-blocklist)"; return 1; }
		_bllib=$(ldd "$SBIN/iked" 2>/dev/null | awk '/libblocklist/ { print $3; exit }')
		FEAT_BLSOCK=$(grep -aoE '/[a-z/]*blocklistd[a-z]*\.sock' "${_bllib:-/nonexistent}" 2>/dev/null | head -1)
		[ -n "$FEAT_BLSOCK" ] || { log "FAIL: no blocklistd socket path in libblocklist '${_bllib:-?}'"; return 1; }
		log "libblocklist $_bllib reports to $FEAT_BLSOCK (sink in a private /run)"
		feat_bl_sink
		printf 'r2-wrong-psk-for-blocklist-rows' > "$C/psk-bad"; chmod 600 "$C/psk-bad"
		BADPSK_I="		kmp_auth_method { psk; };
		pre_shared_key \"$C/psk-bad\";"
		case $name in
		feat-bl-off-i2i) BL_IF= ;;
		feat-bl-logonly-i2i) BL_IF='	blocklist on;
	blocklist_log_only on;' ;;
		feat-bl-prehs-on-i2i) BL_IF='	blocklist on;
	blocklist_prehandshake on;' ;;
		*) BL_IF='	blocklist on;' ;;
		esac
		case $name in
		feat-bl-off-i2i|feat-bl-on-i2i|feat-bl-logonly-i2i) AUTH_I=$BADPSK_I ;;
		feat-bl-on-charon) CH_SEC="	ike-a {
		secret = 0x$(printf 'r2-wrong-psk-for-blocklist-rows' | od -An -tx1 | tr -d ' \n')
	}" ;;
		feat-bl-init-charonr) CH_SEC="	ike-a {
		secret = 0x$(printf 'r2-wrong-psk-for-blocklist-rows' | od -An -tx1 | tr -d ' \n')
	}"
			BL_ROLE=i ;;
		esac
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
	case $name in feat-mai-nosup-*|feat-mai-badpsk-*|feat-mai-off-*|feat-mai-nopeer-charon) want_up=0 ;;
	feat-bl-off-i2i|feat-bl-on-i2i|feat-bl-logonly-i2i|feat-bl-on-charon|feat-bl-init-charonr) want_up=0 ;; esac
	if [ "$want_up" = 1 ]; then
		[ "$up" = 1 ] || { feat_bad "SA/ESP not up"; }
		[ "$up" = 1 ] && i2i_dataplane "$NSI" "$HR" "$name"
	else
		[ "$up" = 0 ] && [ "${re:-0}" = 0 ] && [ "${ie:-0}" = 0 ] ||
		    { feat_bad "an ESP SA landed on a row that must refuse (resp=$re init=$ie)"; }
	fi
	need() {	# need <file> <ERE> <what>
		if grep -qE -- "$2" "$1" 2>/dev/null; then feat_ok "$3"
		else feat_bad "$3 (/$2/ not in ${1##*/})"; fi
	}
	never() {	# never <file> <ERE> <what>
		if grep -qE -- "$2" "$1" 2>/dev/null; then
			feat_bad "$3 ($(grep -E -- "$2" "$1" | head -1))"
		else feat_ok "$3"; fi
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
		need "$RL" 'multiple auth: first round verified, awaiting the second round' "responder verified round one (RSA)"
		need "$IL" 'multiple auth: responder verified, second round \(PSK\) sent' "initiator sent round two"
		need "$RL" 'multiple auth: second round \(PSK\) verified' "responder verified round two (PSK as r2second)"
		need "$IL" 'INI_IKE_AUTH_RCVD -> ESTABLISHED' "initiator ESTABLISHED"
		need "$RL" '-> ESTABLISHED' "responder ESTABLISHED"
		;;
	feat-mai-badpsk-i2i)
		need "$IL" 'second round \(PSK\) sent' "initiator ran round two"
		need "$RL" 'multiple auth: second round \(PSK\) verification failed' "responder rejected the round-two PSK"
		never "$RL" 'second round \(PSK\) verified' "no round-two success"
		never "$IL" 'ESTABLISHED' "initiator never ESTABLISHED"
		;;
	feat-mai-nosup-i2i)
		never "$RL" 'advertising MULTIPLE_AUTH_SUPPORTED' "responder (multiple_auth off) did not advertise"
		need "$IL" 'did not send MULTIPLE_AUTH_SUPPORTED; aborting' "initiator refused the single-round fallback"
		never "$IL" 'ESTABLISHED' "initiator never ESTABLISHED"
		;;
	feat-mai-charon)
		need "$CI" 'generating IKE_AUTH request 1 .*N\(AUTH_FOLLOWS\)' "charon flagged round one"
		need "$RL" 'multiple auth: first round verified, awaiting the second round' "iked verified round one (RSA)"
		need "$RL" 'multiple auth: second round \(PSK\) verified' "iked verified charon's PSK round as r2second"
		need "$CI" 'IKE_SA r2feat\[[0-9]+\] established' "charon ESTABLISHED"
		;;
	feat-mai-nopeer-charon)
		never "$CI" 'generating IKE_SA_INIT request 0 .*N\(MULT_AUTH\)' "charon sent no MULTIPLE_AUTH_SUPPORTED"
		# strongSwan without multiple_authentication does not flag
		# AUTH_FOLLOWS either: it runs one round.  The iked responder
		# names a second identity, so one round must not establish.
		never "$CI" 'generating IKE_AUTH request 1 .*N\(AUTH_FOLLOWS\)' "charon ran a single round"
		need "$RL" 'multiple auth: refused \(multi_auth_second_id requires a second round, peer ran one\)' "iked refused the single-round peer"
		never "$RL" 'second round \(PSK\) verified' "no second round ran"
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
			[ "$n" -eq 1 ] && feat_ok "honor off: one IKE_SA_INIT in 35 s" ||
			    { feat_bad "honor off but $n IKE_SA_INIT initiations"; }
		else
			cap=$(grep -oE 'AUTH_LIFETIME: IKE SA lifetime capped to [0-9]+s' "$IL" | head -1 | grep -oE '[0-9]+s$' | tr -d s)
			if [ -n "$cap" ] && [ "$cap" -ge 15 ] && [ "$cap" -le 30 ]; then feat_ok "cap ${cap}s (<=30)"
			else feat_bad "no AUTH_LIFETIME cap in 15..30 s (got '${cap:-none}')"; fi
			if [ -n "$t2" ] && [ $((t2 - t1)) -ge 10 ] && [ $((t2 - t1)) -le 34 ]; then
				feat_ok "reauth (fresh IKE_SA_INIT) $((t2 - t1)) s after the first"
			else feat_bad "no fresh IKE_SA_INIT 10..34 s after the first (n=$n)"; fi
			k=0; while [ "$k" -lt 15 ]; do
				[ "$(grep -c 'INI_IKE_AUTH_RCVD -> ESTABLISHED' "$IL")" -ge 2 ] && break; sleep 1; k=$((k+1))
			done
			ne=$(grep -c 'INI_IKE_AUTH_RCVD -> ESTABLISHED' "$IL")
			ie=$(ip netns exec "$NSI" ip xfrm state 2>/dev/null | grep -c 'proto esp')
			if [ "$ne" -ge 2 ] && [ "${ie:-0}" -ge 2 ] && ip netns exec "$NSI" ping -c2 -W2 "$HR" >/dev/null 2>&1; then
				feat_ok "reauthenticated SA ESTABLISHED ($ne full IKE_AUTHs), ESP $ie, ping ok"
			else feat_bad "reauthenticated SA not up (IKE_AUTH established=$ne esp=$ie)"; fi
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
				feat_ok "charon reauthenticated $((t2 - t1)) s after AUTH_LIFETIME 30"
			else feat_bad "charon did not reauthenticate within 31 s"; fi
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
	feat-bl-*)
		BS=$D/blsink.log BLL=$RL; [ "$BL_ROLE" = i ] && BLL=$IL
		case $name in feat-bl-prehs-*)
			# 8-byte datagram to 500: shorter than an ISAKMP header
			# from a third address outside the /32 selectors, so the
			# junk is plain UDP (the tunnel policy covers only HI<->HR)
			ip netns exec "$NSI" ip addr add 192.0.7.3/24 dev "$VI"
			ip netns exec "$NSI" python3 -c 'import socket,sys; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(("192.0.7.3",40500)); s.sendto(b"\x01"*8,(sys.argv[1],500))' "$HR"
			sleep 2
			need "$BLL" 'packet \(8\) shorter than isakmp header' "responder classified the junk as pre-handshake (short packet)"
		esac
		sleep 1
		need "$BS" '^SINK ready' "sink bound to libblocklist's socket"
		nr=$(grep -c '^BL ' "$BS" 2>/dev/null); nf=$(grep -c "^BL type=1 af=2 addr=$HI fds=1 why=iked AUTH_FAILED\$" "$BS" 2>/dev/null)
		nk=$(grep -c "^BL type=2 af=2 addr=$HI fds=1 why=iked AUTH_OK\$" "$BS" 2>/dev/null)
		np=$(grep -c "^BL type=1 af=2 addr=192.0.7.3 fds=1 why=iked shortpacket\$" "$BS" 2>/dev/null)
		log "sink: reports=$nr auth_fail=$nf auth_ok=$nk shortpacket=$np"
		_bl_eq() { [ "$1" -eq "$2" ] && log "GATE ok: $3 ($1)" || { log "FAIL: $3: got $1, want $2"; efail=1; }; }
		case $name in
		feat-bl-off-i2i)
			need "$BLL" 'blocklist: off' "iked logged blocklist off"
			need "$BLL" 'authentication failure' "responder rejected the PSK"
			_bl_eq "$nr" 0 "no report while blocklist is unset" ;;
		feat-bl-on-i2i|feat-bl-on-charon)
			need "$BLL" 'blocklist: on' "iked logged blocklist on"
			need "$BLL" "blocklist: reported AUTH_FAIL $HI" "iked reported the failed peer"
			_bl_eq "$nf" 1 "one AUTH_FAIL (BL_ADD) for $HI with the socket fd"
			_bl_eq "$nr" "$nf" "nothing else reported" ;;
		feat-bl-ok-i2i)
			_bl_eq "$nk" 1 "one AUTH_OK (BL_DELETE) for $HI"
			_bl_eq "$nr" 1 "nothing else reported" ;;
		feat-bl-logonly-i2i)
			need "$BLL" 'blocklist: log-only' "iked logged log-only"
			need "$BLL" "blocklist\(log-only\): would report AUTH_FAIL $HI" "iked logged the would-be report"
			_bl_eq "$nr" 0 "log-only sends nothing" ;;
		feat-bl-prehs-off-i2i)
			never "$BLL" 'pre-handshake reports on' "pre-handshake class off"
			_bl_eq "$np" 0 "unverified pre-handshake source not reported"
			_bl_eq "$nr" "$nk" "only the AUTH_OK was reported" ;;
		feat-bl-prehs-on-i2i)
			need "$BLL" 'blocklist: on, pre-handshake reports on' "pre-handshake class on"
			_bl_eq "$np" 1 "short packet reported (BL_ADD, why=iked shortpacket)"
			_bl_eq "$nr" $((nk + np)) "nothing but AUTH_OK and the short packet" ;;
		feat-bl-init-charonr)
			need "$BLL" 'blocklist: on' "initiator iked has blocklist on"
			need "$CR" 'generating IKE_AUTH response 1 \[ N\(AUTH_FAILED\) \]' "charon refused the PSK (IKE_AUTH failed)"
			need "$BLL" 'message lacks IDr payload|AUTHENTICATION_FAILED|authentication failure' "iked initiator saw the failed IKE_AUTH"
			never "$BLL" 'blocklist: reported' "initiator reported nobody"
			_bl_eq "$nr" 0 "no report from the initiator seat" ;;
		esac
		;;
	esac
	if grep -q 'key exchange method ML_KEM_768 not supported' "$CR" 2>/dev/null; then
		feat_bad "this strongSwan has no ML-KEM-768 but the ADDKE iked initiator offers it as mandatory; run -charonr rows against an ML-KEM strongSwan or a classical iked build"
	fi
	if [ "$efail" -ne 0 ]; then	# evidence for a failed row in the job log
		for _f in "$CI" "$CR" "$D/swanctl-load.log" "$D/swanctl-init.log"; do
			[ -s "$_f" ] || continue
			log "--- tail ${_f##*/}"; tail -25 "$_f" | sed 's/^/    /'
		done
		dmesg 2>/dev/null | grep -i 'apparmor.*DENIED' | tail -5 | sed 's/^/    /'
	fi
	if [ "$PEER" = charon ] || [ "$PEER_R" = charon ]; then i2i_charon_kill; fi
	pkill -9 -f "$C/" 2>/dev/null || true
	[ "$efail" -eq 0 ] && log "PASS $name"
	return "$efail"
}
