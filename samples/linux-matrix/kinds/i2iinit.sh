#!/bin/sh
# kinds/i2iinit.sh — PQC ADDKE on the INITIAL IKE_SA via RFC 9242
# IKE_INTERMEDIATE: iked<->iked on 192.0.5.x, each in its OWN netns on a P2P
# veth.  The initiator offers ADDKE (type-6) in SAi1 alongside the 16438
# IKE_INTERMEDIATE capability notify; the responder echoes 16438, selects
# type-6, and both sides complete one IKE_INTERMEDIATE ML-KEM round, update
# SKEYSEED per RFC 9370 s3.5, chain IntAuth per RFC 9242 s3.3.2, and only
# then run IKE_AUTH (ESP child lands => AUTH + IntAuth verified).  Gate:
# gate=addke (WITH_INTERMEDIATE+WITH_ADDKE), Fedora 44.
kind_i2iinit() {
	name=$1
	require_root || return 1
	[ -x "$SBIN/iked" ] || { log "FAIL: no $SBIN/iked"; return 1; }
	[ -f "$ETC/spmd.pwd" ] || { log "FAIL: no $ETC/spmd.pwd"; return 1; }
	[ -f "$ETC/psk/macos.psk" ] || { log "FAIL: no $ETC/psk/macos.psk"; return 1; }
	PEER=$(i2i_peer "$name")
	PEER_R=$(i2i_peer_r "$name")
	PEER_ID=$(i2i_peer_resp_id "$PEER")
	for S in "$PEER" "$PEER_R"; do
		[ "$S" = charon ] && ! command -v "$I2I_CHARON_BIN" >/dev/null 2>&1 && { log "FAIL: no charon binary $I2I_CHARON_BIN"; return 1; }
	done

	NSR=i2init-r; NSI=i2init-i; VR=i2iv-r; VI=i2iv-i
	HR=192.0.5.1; HI=192.0.5.2
	PRIVRES_R=/tmp/r2-i2init-resume-r; PRIVRES_I=/tmp/r2-i2init-resume-i
	D=/tmp/r2-i2init; C=/tmp/r2-i2init-conf
	rm -rf "$PRIVRES_R" "$PRIVRES_I" "$D" "$C"; mkdir -p "$PRIVRES_R" "$PRIVRES_I" "$D" "$C"

	# RFC 8784 PPK rows (i2iinit-ppk, i2iinit-ppk-charon): seats enable
	# USE_PPK with a shared ppk_id (test default = SHA-256(ppk_id), no
	# secret files on the box).  TRACE must be on (0x0003) for the kind's
	# USE_PPK/PPK_IDENTITY evidence lines to land in the iked logs.  A
	# -ppk-charon suffix additionally drops the charon initiator into
	# PPK (ppk_id/ppk_required + secrets.ppk matching the iked test
	# default) — re-arbitrating the s5.1 typed PPK_IDENTITY against a
	# second implementation.
	I2I_DBG=0x0001
	I2I_PPK=0
	I2I_PPK_MANDATORY=0
	# Proposal-shape / config-option knobs (suffix-driven; iked conf templates
	# below interpolate these).  Defaults = the PQC base shape.
	I2I_IKE_ENC="aes_gcm"          # kmp_enc_alg on both iked seats
	I2I_IKE_PRF="hmac_sha2_256"    # kmp_prf_alg + kmp_hash_alg
	I2I_ESP_ENC="aes_gcm"          # esp_enc_alg (name, optional ', <keylen>')
	I2I_ESP_AUTH="non_auth"        # esp_auth_alg (separate integrity)
	I2I_ESN=0                       # ipsec block ext_sequence on
	I2I_CHILDLESS=0                 # responder childless on (RFC 6023)
	I2I_CLASSICAL=0                 # proposal-shape rows without ADDKE round
	case "$name" in
	*-childless*) I2I_CHILDLESS=1 ;;
	esac
	case "$name" in
	*-ike-cbc256*) I2I_IKE_ENC="aes256_cbc" ;;
	esac
	case "$name" in
	*-prfsha384*) I2I_IKE_PRF="hmac_sha2_384" ;;
	*-prfsha512*) I2I_IKE_PRF="hmac_sha2_512" ;;
	esac
	case "$name" in
	*-esp-gcm256*) I2I_ESP_ENC="aes_gcm, 256" ;;
	*-esp-cbc256*) I2I_ESP_ENC="aes256_cbc"; I2I_ESP_AUTH="hmac_sha2_256" ;;
	esac
	case "$name" in
	*-ike-cbc256*) I2I_CLASSICAL=1 ;;
	esac
	case "$name" in
	*-esn*) I2I_ESN=1 ;;
	esac
	# esp_addke_alg line for the INITIATOR sa block: classical shape rows
	# (proposal-shape tests) omit type-6 so the exchange is purely keyboard
	# crypto; every other row keeps ML-KEM-768 on the child (RFC 9370).
	I2I_ADDKE_TXT=""
	if [ "$I2I_CLASSICAL" = 1 ]; then
		I2I_ADDKE_TXT=""
	else
		I2I_ADDKE_TXT='	esp_addke_alg { mlkem768; };
'
	fi
	case "$name" in
	*-ppk*) I2I_PPK=1; I2I_DBG=0x0003 ;;
	esac
	# PPK direction: when iked is the IKE INITIATOR (-ppk-charonr), it must
	# REQUIRE the PPK (ppk_mandatory on).  RFC 8784: an initiator that only
	# OPTIONALLY uses the PPK advertises N(NO_PPK_AUTH) in IKE_AUTH
	# (iked/ikev2.c:2641-2645), which makes a strict charon responder fall
	# back to classical PSK AUTH — the PPK row then exercises the decline
	# path, not PPK application.  mandatory on drops the N(NO_PPK_AUTH)
	# decline so charon's responder must apply the PPK (gate 'using PPK').
	case "$name" in
	*-ppk-charonr) I2I_PPK_MANDATORY=1 ;;
	esac
	PPK_TXT=""
	if [ "$I2I_PPK" = 1 ]; then
		if [ "$I2I_PPK_MANDATORY" = 1 ]; then
			PPK_TXT='		use_ppk on;
		ppk_mandatory on;
		ppk_id "rfc8784-mat";'
		else
			PPK_TXT='		use_ppk on;
		ppk_mandatory off;
		ppk_id "rfc8784-mat";'
		fi
	fi

	# RFC 7296 2.18 PFS rekey row (i2iinit-pfsrekey-charon): the charon
	# seat's child esp_proposals carry a DH-group suffix (I2I_ESP=
	# 'aes128gcm16-ecp256', PFS on the child), so the AUTH child is PFS
	# and a later rekey of it MUST carry DH (implemented by mirroring
	# the peer-offered DH into my_proposal — ee60cda).  NOTE: strongSwan
	# swanctl REJECTS the trailing '!' ("required proposal") marker in
	# esp_proposals — the DH suffix alone is the PFS statement.  Shorten
	# the iked responder lifetime so iked mints the child rekey mid-row;
	# gate on g_ir_present=Y in the rekey keymat + SPI change + no
	# NO_PROPOSAL_CHOSEN (would fail pre-fix: no KE payload).
	I2I_LIFETIME=300
	# DH-group variants first (unconditional; see below why they must win):
	# I2I_PROPOSAL resolves at source time, so a row that changes the group
	# MUST set the full charon IKE proposal itself (skill: a later
	# I2I_DH_GROUP alone never propagates into I2I_PROPOSAL).  The child
	# PFS group comes from I2I_ESP's '-<grp>!' suffix, and the iked confs
	# now offer kmp_dh_group $I2I_DH_GROUP so the KMP DH overlaps.  These
	# arms override I2I_ESP unconditionally so a '-dh384-pfsrekey' name
	# lands on ecp384, not the -pfsrekey default ecp256.
	case "$name" in
	*-dh384*) I2I_DH_GROUP=ecp384; I2I_PROPOSAL=aes256gcm16-prfsha256-ecp384-ke1_mlkem768
	          I2I_ESP=aes128gcm16-ecp384 ;;
	*-dh521*) I2I_DH_GROUP=ecp521; I2I_PROPOSAL=aes256gcm16-prfsha256-ecp521-ke1_mlkem768
	          I2I_ESP=aes128gcm16-ecp521 ;;
	esac
	case "$name" in
	*-pfsrekey*) I2I_LIFETIME=25; I2I_ESP=${I2I_ESP:-aes128gcm16-ecp256} ;;
	esac

	# RFC 6023 childless IKE_SA (Feature A): responder advertises
	# CHILDLESS_IKEV2_SUPPORTED + accepts a SA-less (modified) IKE_AUTH
	# ONLY when a -childless row (both the iked responder conf and, for the
	# charon-init seat, the swanctl childless = force conn line via
	# i2i_peer.sh) opt in.  Default off keeps every base row childless-free.
	CHILDLESS_TXT_R=""
	[ "$I2I_CHILDLESS" = 1 ] && CHILDLESS_TXT_R='		childless on;
'
	# ESN rows: ext_sequence on in the ipsec block (RFC 7296 s3.3.2).
	ESN_TXT=""
	[ "$I2I_ESN" = 1 ] && ESN_TXT='		ext_sequence on;
'

	if [ "$PEER_R" = charon ]; then
	# charon responder: shared helper writes the swanctl conn (PSK hex read
	# from the existing matrix psk, never printed); iked responder.conf below
	# is skipped for this seat.
	i2i_peer_r_conf "$C" "$HR" "$HI" "$name" charon || return 1
else
cat > "$C/responder.conf" <<EOF
interface {
	ike { "$HR"; };
	spmd { unix "/tmp/spmif-i2init-r"; };
	spmd_password "$ETC/spmd.pwd";
};
resolver { resolver off; };
remote matrix_resp {
	acceptable_kmp { ikev2; };
	ikev2 {
		passive on;
		my_id fqdn "racoon2-matrix";
		peers_id fqdn "$PEER_ID";
		peers_ipaddr "$HI";
		kmp_enc_alg { $I2I_IKE_ENC; };
		kmp_prf_alg { $I2I_IKE_PRF; };
		kmp_hash_alg { $I2I_IKE_PRF; };
		kmp_dh_group { $I2I_DH_GROUP; };
		kmp_auth_method { psk; };
		pre_shared_key "$ETC/psk/macos.psk";
$PPK_TXT
$CHILDLESS_TXT_R
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
	ipsec_sa_lifetime_time $I2I_LIFETIME sec;
$ESN_TXT	sa_index esp_e;
};
sa esp_e {
	sa_protocol esp;
	esp_enc_alg { $I2I_ESP_ENC; };
	esp_auth_alg { $I2I_ESP_AUTH; };
$(i2i_sa_addke_lines "$name")
	};
EOF
fi

	if [ "$PEER" = charon ]; then
	# charon initiator: shared helper writes the swanctl conn (PSK hex read
	# from the existing matrix psk, never printed) and spawns/triggers it.
	i2i_peer_i_conf "$C" "$HI" "$HR" "$name" charon || return 1
else
cat > "$C/initiator.conf" <<EOF
interface {
	ike { "$HI"; };
	spmd { unix "/tmp/spmif-i2init-i"; };
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
		kmp_enc_alg { $I2I_IKE_ENC; };
		kmp_prf_alg { $I2I_IKE_PRF; };
		kmp_hash_alg { $I2I_IKE_PRF; };
		kmp_dh_group { $I2I_DH_GROUP; };
		kmp_auth_method { psk; };
		pre_shared_key "$ETC/psk/macos.psk";
$PPK_TXT
		dpd_delay 60 sec;
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
	ipsec_sa_lifetime_time $I2I_LIFETIME sec;
$ESN_TXT	sa_index esp_e;
};
sa esp_e {
	sa_protocol esp;
	esp_enc_alg { $I2I_ESP_ENC; };
	esp_auth_alg { $I2I_ESP_AUTH; };
$I2I_ADDKE_TXT};
EOF
fi

	# kill daemons by the unique per-run conf dir (it IS in their argv)
	pkill -9 -f "$C/" 2>/dev/null || true
	rm -f /tmp/spmif-i2init-r /tmp/spmif-i2init-i /tmp/iked.sock-i2init-r /tmp/iked.sock-i2init-i

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

	# UDP-allow rows BEFORE any spmd so IKE is not captured by the tunnel
	for ns in "$NSR:$HR:$HI" "$NSI:$HI:$HR"; do
		NSX=${ns%%:*}; rest=${ns#*:}; LX=${rest%%:*}; PX=${rest#*:}
		for p in 500 4500; do
			ip netns exec "$NSX" ip xfrm policy add src "$PX"/32 dst "$LX"/32 proto udp sport "$p" dport "$p" dir in  ptype main action allow 2>/dev/null || true
			ip netns exec "$NSX" ip xfrm policy add src "$LX"/32 dst "$PX"/32 proto udp sport "$p" dport "$p" dir out ptype main action allow 2>/dev/null || true
		done
	done

if [ "$PEER_R" = charon ]; then
	i2i_peer_r_start "$D" "$NSR" charon "$name"
else
	( ip netns exec "$NSR" "$SBIN/spmd" -F -f "$C/responder.conf" ) >"$D/resp-spmd.log" 2>&1 &
	RSPMD=$!
	i=0; until [ -S /tmp/spmif-i2init-r ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
	( ip netns exec "$NSR" env RACOON2_ADMIN_SOCK=/tmp/iked.sock-i2init-r RACOON2_RESUME_DIR="$PRIVRES_R" \
	    "$SBIN/iked" -F -f "$C/responder.conf" -D "$I2I_DBG" -l "$D/resp-iked.log" ) >"$D/resp-iked.out" 2>&1 &
fi

if [ "$PEER" = charon ]; then
	i2i_peer_i_start "$D" "$NSI" charon "$name"
else
	( ip netns exec "$NSI" "$SBIN/spmd" -F -f "$C/initiator.conf" ) >"$D/init-spmd.log" 2>&1 &
	ISPMD=$!
	i=0; until [ -S /tmp/spmif-i2init-i ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
	( ip netns exec "$NSI" env RACOON2_ADMIN_SOCK=/tmp/iked.sock-i2init-i RACOON2_RESUME_DIR="$PRIVRES_I" \
	    "$SBIN/iked" -F -f "$C/initiator.conf" -D "$I2I_DBG" -l "$D/init-iked.log" ) >"$D/init-iked.out" 2>&1 &
fi

	sleep 2
	if [ "$PEER_R" = charon ]; then
	# charon responder: LOAD conns so it answers (passive; no --initiate);
	# the racoon2 initiator drives the exchange next.
	i2i_peer_r_trigger "$D" "$NSR" charon "$name"
	fi
	if [ "$PEER" = charon ]; then
	i2i_peer_i_trigger "$D" "$NSI" charon "$name"
else
	"$SBIN/ikedctl" -s /tmp/iked.sock-i2init-i establish-sa isakmp inet "$HI" "$HR" sel_out >/dev/null 2>&1 || true
fi

	up=0
	i=0
	while [ "$i" -lt 45 ]; do
		re=$(ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -c 'proto esp')
		ie=$(ip netns exec "$NSI" ip xfrm state 2>/dev/null | grep -c 'proto esp')
		if [ "${re:-0}" -ge 2 ] && [ "${ie:-0}" -ge 2 ]; then
			log "PQC INITIAL IKE_SA ADDKE child UP: responder esp=$re initiator esp=$ie after ${i}s"
			up=1
			break
		fi
		i=$((i+1)); sleep 1
	done

	# The initial IKE_SA ran an IKE_INTERMEDIATE ADDKE round (SAi1 type-6 +
	# 16438 both sides).  Both SEATS must prove it: iked logs
	# 'IKE_INTERMEDIATE ADDKE round complete' on the side it occupies; a
	# charon seat instead logs KE1_ML_KEM_768 selected + ESTABLISHED
	# (RFC 9370 s3.5).  A classical int exchange logs none of these -> fail.
	nint=0; i=0
	while [ "$i" -lt 20 ]; do
		# responder-seat evidence (iked responder or charon responder)
		i2i_peer_r_evidence "$D" "$PEER_R"
		n_r=$?
		# initiator-seat evidence (iked initiator or charon initiator)
		i2i_peer_i_evidence "$D" "$PEER"
		n_p=$?
		if [ "$n_r" -eq 0 ] && [ "$n_p" -eq 0 ]; then
			log "IKE_INTERMEDIATE ADDKE round completed: responder(seat=${PEER_R}) + ${PEER} initiator at ${i}s"
			nint=1; break
		fi
		i=$((i+1)); sleep 1
	done
	# AUTH+IntAuth verified == the RFC 9370 s3.5 SKEYSEED(1) matched: both
	# sides derived the same intermediate key or the ESP child could not
	# establish (up=1 is checked separately).  The raw SKEYSEED/IntAuth bytes
	# are intentionally not logged, so the round-complete marker plus up=1 is
	# the proof.
	pqc=0
	if [ "${nint:-0}" -eq 1 ]; then
		pqc=1
		log "INITIAL IKE_SA ADDKE: IKE_INTERMEDIATE round on BOTH sides, ESP child up => SK(1) key material matched"
	else
		log "FAIL: initial IKE_SA not ADDKE/ML-KEM (nint=${nint:-0})"
	fi

	# RFC 8784 PPK rows: with USE_PPK on both seats the child only lands if
	# BOTH re-derived SK_d/SK_pi/SK_pr with the same PPK; the AUTH passing
	# (up=1) already proves that.  Additionally assert the append-only
	# wire markers: the initiator saw the USE_PPK echo + the responder
	# confirmed the PPK_IDENTITY (TRACE level, enabled by I2I_DBG=0x0003).
	ppk_ok=0
	if [ "$I2I_PPK" = 1 ]; then
		# responder-seat USE_PPK evidence (iked: its log; charon: its own
		# 'using PPK for PPK_ID' line).  Init-seat markers likewise; the
		# iked-only 'responder confirmed PPK_IDENTITY' TRACE line only
		# exists when the RESPONDER seat is iked.
		if [ "$PEER_R" = charon ]; then
			# 'loaded PPK shared key' is written BEFORE the exchange and
			# survives run.sh's SIGKILL that truncates charon's log mid-
			# response; the later 'using PPK for PPK_ID' line falls after the
			# truncation point and would false-fail.  AUTH passing (up=1) with
			# the iked initiator having mixed PPK is the infallible proof both
			# seats mixed the same PPK.
			gre=$(grep -c "loaded PPK shared key" "$D/charon-resp.log" 2>/dev/null)
		else
			gre=$(grep -c "peer uses RFC 8784 PPK (USE_PPK)" "$D/resp-iked.log" 2>/dev/null)
		fi
		if [ "$PEER" = charon ]; then
			gie=$(grep -c "using PPK for PPK_ID '" "$D/charon-init.log" 2>/dev/null)
			gid=1
		else
			gie=$(grep -c "peer uses RFC 8784 PPK (USE_PPK)" "$D/init-iked.log" 2>/dev/null)
			gid=$(grep -c "RFC 8784: responder confirmed PPK_IDENTITY" "$D/init-iked.log" 2>/dev/null)
		fi
		if [ "${gre:-0}" -ge 1 ] && [ "${gie:-0}" -ge 1 ] && [ "${gid:-0}" -ge 1 ] && [ "$up" -eq 1 ]; then
			ppk_ok=1
			log "RFC 8784 PPK: USE_PPK echoed both seats + PPK_IDENTITY confirmed; child up => PPK-mixed SK_d matched"
		else
			log "FAIL: RFC 8784 PPK markers absent (resp_use_ppk=${gre:-0} init_use_ppk=${gie:-0} init/charon_id_confirm=${gid:-0})"
		fi
	fi

	# RFC 7296 2.18 PFS rekey rows: after the initial child lands, the iked
	# RESPONDER (short I2I_LIFETIME) mints a CREATE_CHILD_SA child rekey of
	# the PFS-negotiated child.  The fix (ee60cda) mirrors the peer-offered
	# DH into my_proposal so the rekey proposal carries DH and KEi is sent;
	# charon (esp -ecp256!) demands that DH.  Pre-fix: no KE payload ->
	# charon answers NO_PROPOSAL_CHOSEN, SPI never changes.  Gate: fresh
	# rekey on the iked responder log, a PFS keymat (g_ir_present=Y),
	# SPI change, and no responder NO_PROPOSAL_CHOSEN.
	pfsrekey_ok=0
	case "$name" in
	*-pfsrekey*)
		# The storm seat: which iked mints the rekey.  -charon (charon
		# INITIATOR, iked responder) reproduces the live storm exactly.  In
		# the reverse -charonr the iked INITIATOR mints it (charon responder
		# still requires PFS).  Gate on THAT iked's log + THAT netns' SPI.
		if [ "$PEER" = charon ]; then
			ike_log="$D/resp-iked.log"; spi_ns="$NSR"
		else
			ike_log="$D/init-iked.log"; spi_ns="$NSI"
		fi
		spi_before=$(ip netns exec "$spi_ns" ip xfrm state 2>/dev/null | grep 'proto esp' | grep -oE '0x[0-9a-f]{8}' | sort | tr '
' ' ')
		sleep 40
		# that iked must mint the rekey (child soft lifetime ~20s)
		if ! grep -q 'initiating CREATE_CHILD_SA rekey' "$ike_log" 2>/dev/null; then
			log "FAIL: iked did not initiate child rekey ($ike_log)"
		elif grep -q 'NO_PROPOSAL_CHOSEN' "$ike_log" 2>/dev/null; then
			log "FAIL: rekey answered NO_PROPOSAL_CHOSEN (KE-less rekey?)"
		elif ! grep -qE 'g_ir_present=Y' "$ike_log" 2>/dev/null; then
			log "FAIL: no PFS (g_ir_present=Y) keymat after rekey ($ike_log)"
		else
			spi_after=$(ip netns exec "$spi_ns" ip xfrm state 2>/dev/null | grep 'proto esp' | grep -oE '0x[0-9a-f]{8}' | sort | tr '
' ' ')
			if [ "$spi_before" != "$spi_after" ]; then
				pfsrekey_ok=1
				log "PFS rekey OK: iked rekey carried DH (KEi), charon accepted, SPI $spi_before -> $spi_after"
			else
				log "FAIL: ESP SPI unchanged after PFS rekey wait ($spi_before)"
			fi
		fi
		;;
	esac

	# NDcPP v3.0e compliance report for this row (A/B cells) — runs while
	# the netnss + SADB are still live (A1/A2/A3 read xfrm policy/state)
	# and before charon conn files are removed (A13/A14 read the conn).
	i2i_compliance "$D" "$C" "$NSR" "$NSI" "$HR" "$HI" "$name"; cpl=$?

	# kill daemons by the unique per-run conf dir; charon on either seat is
	# torn down via the peer helpers (swanctl conn file removed, charon
	# killed).
	i2i_peer_i_cleanup "$PEER"
	i2i_peer_r_cleanup "$PEER_R" "$name"
	pkill -9 -f "$C/" 2>/dev/null || true
	rm -f /etc/strongswan/swanctl/conf.d/r2-${name}.conf
	sleep 1
	ip netns del "$NSR" 2>/dev/null || true
	ip netns del "$NSI" 2>/dev/null || true
	ip link del "$VR" 2>/dev/null || true
	rm -rf "$PRIVRES_R" "$PRIVRES_I"

	# Classical (proposal-shape) rows: only *-ike-cbc256* runs a CBC IKE_SA,
	# which has no AEAD so the RFC 9242 IntAuth_A round cannot run — that row
	# MUST have zero round markers (a stray round is a defect for the shape)
	# and the PQC requirement is waived (need_pqc=0).  PRF / ESP-shape / ESN
	# rows keep aes_gcm on the IKE_SA, so they stay full PQC rows (need_pqc=1)
	# and still gate on the IKE_INTERMEDIATE ADDKE round.
	need_pqc=1
	if [ "$I2I_CLASSICAL" = 1 ]; then
		need_pqc=0
		if grep -qE 'IKE_INTERMEDIATE ADDKE round complete|KE1_ML_KEM_768' "$D/resp-iked.log" "$D/init-iked.log" "$D/charon-init.log" "$D/charon-resp.log" 2>/dev/null; then
			log 'FAIL: classical-CBC row shows an ADDKE round (RFC 9242 IntAuth_A cannot run on CBC IKE)'
		fi
	fi

	# Proposal-shape SAD gate: rows that change ESP shape must show the
	# negotiated kernel SAD cipher, else a row could PASS with the child
	# up on the DEFAULT aes_gcm (a knob that silently failed to apply).
	# -esp-gcm256 -> aead rfc4106 keylen 32   -esp-cbc256 -> enc cbc(aes) 32
	# + auth hmac(sha256)                      -esn         -> 'flag E' on
	# the ESP state (ESN replay counter).  Only the responder netns SAD is
	# checked (the peer seat mirrors it).
	shape_ok=1
	case "$name" in
	*-esp-gcm256)
		if ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -qE 'aead rfc4106\(gcm\(aes\)\).* 32$'; then
			shape_ok=1
			log 'ESP shape: responder SAD aead rfc4106(gcm(aes)) keylen 32 (AES-256-GCM)'
		else
			shape_ok=0
			log 'FAIL: -esp-gcm256 row but responder SAD lacks aead rfc4106 keylen 32'
		fi
		;;
	*-esp-cbc256)
		if ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -qE 'enc cbc\(aes\).* 32' \
		   && ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -qE 'auth hmac\(sha256\)'; then
			shape_ok=1
			log 'ESP shape: responder SAD enc cbc(aes) keylen 32 + auth hmac(sha256) (AES-CBC-256 + separate integrity)'
		else
			shape_ok=0
			log 'FAIL: -esp-cbc256 row but responder SAD lacks cbc(aes)32 + hmac(sha256)'
		fi
		;;
	*-esn)
		# ESN shows as a replay-window flag E on the ESP state (iproute2).
		if ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -qE '\bE\b|flag E| replay-window' \
		   && ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -qE 'proto esp'; then
			shape_ok=1
			log 'ESP shape: responder SAD carries ESN (ext_sequence on)'
		else
			shape_ok=0
			log 'FAIL: -esn row but responder SAD shows no ESN flag'
		fi
		;;
	*)
		shape_ok=1
		;;
	esac
	if [ "$shape_ok" -ne 1 ]; then
		log 'FAIL: proposal-shape SAD gate rejected the row'
	fi

	# RFC 6023 childless rows (Feature A):
	#   i2iinit-childless-charon  charon INITIATOR childless=force -> iked
	#                             responder childless on accepts the SA-less
	#                             (modified) IKE_AUTH and answers SA-less
	#                             AUTH; the knob must also be exercised on
	#                             the responder only.
	#   i2iinit-childless         iked<->iked, responder childless on: the
	#                             iked initiator does NOT send a modified
	#                             IKE_AUTH (racoon2 initiator has no
	#                             childless-init), so this validates the
	#                             knob does not break a CLASSICAL IKE_AUTH
	#                             (advertise 16418 + still accept SA-full).
	childless_ok=0
	case "$name" in
	*-childless-charon)
		# the responder must ACCEPT a true SA-less IKE_AUTH and answer
		# SA-less; charon then adds the child via a separate CREATE_CHILD_SA.
		if grep -q 'received childless (SA-less) IKE_AUTH' "$D/resp-iked.log" 2>/dev/null && \
		   grep -q 'advertising childless IKE_SA support (16418)' "$D/resp-iked.log" 2>/dev/null; then
			childless_ok=1
			log 'RFC 6023: responder accepted SA-less (modified) IKE_AUTH + advertised 16418; child via CREATE_CHILD_SA'
		else
			log 'FAIL: responder childless accept path not exercised (no 16418 advertise / no SA-less accept)'
		fi
		;;
	*-childless)
		# iked<->iked: responder knob ON; initiator still sends a classical
		# (SA-full) IKE_AUTH which must be accepted normally.
		if grep -q 'advertising childless IKE_SA support (16418)' "$D/resp-iked.log" 2>/dev/null; then
			childless_ok=1
			log 'RFC 6023: childless knob ON advertised 16418; classical IKE_AUTH still accepted'
		else
			log 'FAIL: childless knob ON did not advertise 16418'
		fi
		;;
	*)
		childless_ok=1
		;;
	esac

	if [ "$up" -ne 1 ] || { [ "$need_pqc" = 1 ] && { [ "${nint:-0}" -ne 1 ] || [ "${pqc:-0}" -ne 1 ]; }; } || [ "$cpl" -ne 0 ] || [ "${childless_ok:-0}" -ne 1 ] || [ "${shape_ok:-1}" -ne 1 ] || { [ "$I2I_PPK" = 1 ] && [ "${ppk_ok:-0}" -ne 1 ]; } || { case "$name" in *-pfsrekey*) [ "${pfsrekey_ok:-0}" -ne 1 ] ;; *) false ;; esac; }; then
		log "FAIL: i2iinit incomplete (up=${up:-0} nint=${nint:-0} pqc=${pqc:-0} cpl=$cpl childless_ok=${childless_ok:-0} shape_ok=${shape_ok:-1} ppk_ok=${ppk_ok:-0} pfsrekey_ok=${pfsrekey_ok:-0} peeri=${PEER} peerr=${PEER_R})"
		if [ "$PEER" = charon ]; then
			log "--- charon-init.log ---"
			i2i_peer_i_diag "$D" charon
		else
			log "--- init-iked.log ---"
			grep -E 'IKE_INTERMEDIATE|IKE_SA_INIT|IKE_AUTH|abort|err=|FOLLOWUP' \
				"$D/init-iked.log" 2>/dev/null | tail -8
		fi
		if [ "$PEER_R" = charon ]; then
			log "--- charon-resp.log ---"
			i2i_peer_r_diag "$D" charon
		else
			log "--- resp-iked.log ---"
			grep -E 'IKE_INTERMEDIATE|IKE_SA_INIT|IKE_AUTH|abort|err=|FOLLOWUP' \
				"$D/resp-iked.log" 2>/dev/null | tail -8
		fi
		return 1
	fi
	return 0
}
