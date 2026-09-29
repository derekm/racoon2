#!/bin/sh
# kinds/i2i_peer.sh — peer-backend swap for the i2i-family kinds.
# The i2i kinds default to iked<->iked.  A `-charon` name suffix (or
# R2_PEER_I=charon) runs the SAME kind with a strongSwan charon initiator
# (RFC 9370 ADDKE ke1_mlkem768 + RFC 9242 IKE_INTERMEDIATE) in the
# initiator netns; the responder stays the iked SUT.  This is the interop
# row: charon 6.0.7 (ml plugin) and a WITH_ADDKE iked derive the same
# ML-KEM-768 key material across two independent implementations — the ESP
# child landing proves SK(1) matched (AUTH+IntAuth verify).  iked default
# paths in the kinds stay untouched.
# New -charon rows ship gate=box until a container counted-gate PASS.
# Requires strongSwan 6.0.x + the `ml` plugin on the run host (box:
# libstrongswan-ml.so; mlkem768/ML_KEM_768 in libstrongswan.so.0).

I2I_CHARON_ID=charon-i2i
I2I_CHARON_BIN=${I2I_CHARON_BIN:-/usr/libexec/strongswan/charon}
I2I_SWANCTL_BIN=${I2I_SWANCTL_BIN:-/usr/bin/swanctl}
I2I_CHARON_VDIR=${I2I_CHARON_VDIR:-/etc/strongswan/swanctl/conf.d}
I2I_DH_GROUP=${I2I_DH_GROUP:-ecp256}	# charon IKE proposal DH group
I2I_PROPOSAL=${I2I_PROPOSAL:-aes256gcm16-prfsha256-${I2I_DH_GROUP}-ke1_mlkem768}	# full charon IKE proposal string
# Child (ESP) proposal: ${I2I_ESP:-aes128gcm16} default.  PFS-child rows
# (i2iinit-charonr-pfsrekey) set I2I_ESP='aes128gcm16-ecp256!' so charon
# REQUIRES a DH transform on any child SA it accepts (RFC 7296 2.18.
# rekey-of-PFS-child MUST re-key with PFS; charon answers NO_PROPOSAL_CHOSEN
# to a KE-less rekey).
I2I_ESP=${I2I_ESP:-aes128gcm16}
# RFC 8784 PPK on a charon seat: I2I_PPK=1 adds ppk_id/ppk_required to the
# conn and a secrets.ppk block whose secret is the SAME test default the
# iked seat derives (SHA-256('rfc8784-mat')) — charon sends the typed
# PPK_ID_FIXED (0x02) identity, re-arbitrating our s5.1 type-octet fix
# against a second implementation.  No secret files are created.
I2I_PPK=${I2I_PPK:-0}
I2I_PPK_ID=${I2I_PPK_ID:-rfc8784-mat}
I2I_PPK_HEX=1e9546cc8758e5f4bf1f5d3476f79bfea60c7bd4822a32058e23cf16107eef0b

# i2i_peer <name> — INITIATOR-seat backend for a case: charon when the name
# carries a -charon suffix (or R2_PEER_I=charon globally), else iked.
i2i_peer() {
	case "$1" in
	*-charon) echo charon ;;
	*)        echo "${R2_PEER_I:-iked}" ;;
	esac
}

# i2i_peer_r <name> — RESPONDER-seat backend: charon when the name carries
# a -charonr suffix (or R2_PEER_R=charon globally), else iked.  This is the
# reverse interop direction: racoon2 iked INITIATES, charon 6.0.7 answers
# (swanctl conn loaded passively, no --initiate).
i2i_peer_r() {
	case "$1" in
	*-charonr) echo charon ;;
	*)         echo "${R2_PEER_R:-iked}" ;;
	esac
}

# i2i_peer_resp_id <peer> — the responder's peers_id for this initiator id.
i2i_peer_resp_id() {
	if [ "$1" = charon ]; then echo "$I2I_CHARON_ID"; else echo "r2init-matrix"; fi
}

# ppk_secret_block <name> — emit a swanctl secrets.ppk block when I2I_PPK=1.
# The secret is the SAME deterministic test default the iked seat derives
# (SHA-256(ppk_id)); charon will send the typed PPK_ID_FIXED identity.
# Emits nothing otherwise (so a non-PPK row's secrets{} stays single-cased).
ppk_secret_block() {
	_name=$1
	[ "$I2I_PPK" = 1 ] || return 0
	cat <<SEOF
	ppk-$_name {
		secret = "0x$I2I_PPK_HEX"
		id = "$I2I_PPK_ID"
	}
SEOF
	return 0
}

# i2i_sa_addke_lines <name> — the esp_addke_alg line for an iked sa block.
# pfsrekey rows drop it: the charon peer's esp proposal is plain
# aes128gcm16-ecp256! (no type-6) and a type-6 on a child rekey proposal is
# RFC 9370 CREATE_CHILD-only; keeping the row purely PFS isolates the
# RFC 7296 2.18 DH rekey fix from charon's ADDKE handling.
i2i_sa_addke_lines() {
	case "$1" in
	*-pfsrekey*) return 0 ;;
	esac
	printf '	esp_addke_alg { mlkem768; };
'
	return 0
}

ppk_conn_lines() {
	[ "$I2I_PPK" = 1 ] || return 0
	cat <<PPKL
		ppk_id = "$I2I_PPK_ID"
		ppk_required = yes
PPKL
	return 0
}

# i2i_peer_i_conf <C> <HI> <HR> <name> <peer> — write a swanctl conn for a
# charon initiator; the iked initiator conf stays inline in the kind.  PSK
# hex is read from the existing matrix psk file (never printed, never
# committed); the conf file is removed by i2i_peer_i_cleanup.
i2i_peer_i_conf() {
	_C=$1 _HI=$2 _HR=$3 _name=$4 _peer=$5
	[ "$_peer" = charon ] || return 0
	I2I_CHARON_CONF="$I2I_CHARON_VDIR/r2-${_name}.conf"
	mkdir -p "$I2I_CHARON_VDIR" || return 1
	_pskhex=$(psk_file_hex "$ETC/psk/macos.psk") || { log "FAIL: charon psk hex"; return 1; }
	cat > "$I2I_CHARON_CONF" <<EOF
connections {
	$_name {
		version = 2
		rekey_time = 0s
		proposals = ${I2I_PROPOSAL}
		local_addrs = $_HI
		remote_addrs = $_HR
		local {
			id = $I2I_CHARON_ID
			auth = psk
		}
		remote {
			id = racoon2-matrix
			auth = psk
		}
$(ppk_conn_lines)
		children {
			ch {
				local_ts = $_HI/32
				remote_ts = $_HR/32
				esp_proposals = ${I2I_ESP}
				rekey_time = 0s
			}
		}
	}
}
secrets {
	ike-$_name {
		secret = "0x$_pskhex"
	}
$(ppk_secret_block "$_name")
}
EOF
	return 0
}

# i2i_peer_i_start <D> <NSI> <peer> <name> — spawn the charon initiator in
# its netns (stderr to $D/charon-init.log).  iked spawn stays in the kind.
i2i_peer_i_start() {
	_D=$1 _NSI=$2 _peer=$3 _name=$4
	[ "$_peer" = charon ] || return 0
	( ip netns exec "$_NSI" "$I2I_CHARON_BIN" --debug-ike 3 --debug-knl 1 \
	    --debug-cfg 2 --debug-mgr 2 --debug-net 1 ) >"$_D/charon-init.log" 2>&1 &
	sleep 2
	return 0
}

# i2i_peer_i_trigger <D> <NSI> <peer> <name> — load conns + initiate.  The
# iked trigger (ikedctl establish-sa) stays inline in the kind.
i2i_peer_i_trigger() {
	_D=$1 _NSI=$2 _peer=$3 _name=$4
	[ "$_peer" = charon ] || return 0
	( ip netns exec "$_NSI" "$I2I_SWANCTL_BIN" --load-all --debug 2 ) >"$_D/swanctl-load.log" 2>&1
	( ip netns exec "$_NSI" "$I2I_SWANCTL_BIN" --initiate --child ch --debug 2 ) >"$_D/swanctl-init.log" 2>&1
	return 0
}

# i2i_peer_i_evidence <D> <peer> — this initiator completed its ADDKE side:
# iked logs round-complete; charon selected KE1_ML_KEM_768 and reached
# ESTABLISHED (the ESP child landing elsewhere in the kind proves SK(1)).
i2i_peer_i_evidence() {
	_D=$1 _peer=$2
	if [ "$_peer" = charon ]; then
		grep -q 'KE1_ML_KEM_768' "$_D/charon-init.log" 2>/dev/null &&
		grep -q 'state change: CONNECTING => ESTABLISHED' "$_D/charon-init.log" 2>/dev/null
		return $?
	fi
	grep -q 'IKE_INTERMEDIATE ADDKE round complete' "$_D/init-iked.log" 2>/dev/null
}

# i2i_peer_i_diag <D> <peer> — charon-side failure tail for the FAIL dump.
i2i_peer_i_diag() {
	_D=$1 _peer=$2
	[ "$_peer" = charon ] || return 0
	grep -E 'selected proposal|KE1_ML_KEM_768|state change|not acceptable|no proposal|received proposals' \
		"$_D/charon-init.log" 2>/dev/null | tail -8
}

# i2i_peer_i_cleanup <peer> — stop the charon initiator, drop its swanctl
# conn file.  iked cleanup stays in the kind.
i2i_peer_i_cleanup() {
	_peer=$1
	[ "$_peer" = charon ] || return 0
	# fail loudly, never a silent no-op: a missing killall/procps here would
	# leak charon into the next case (skill: cleanup gates must not no-op).
	command -v killall >/dev/null 2>&1 || { log "FAIL: no killall (psmisc) — charon cleanup would no-op"; return 1; }
	require_procps || return 1
	killall -9 charon 2>/dev/null || true
	rm -f /var/run/charon.pid /var/run/charon.ctl
	rm -f "${I2I_CHARON_CONF:-/nonexistent}"
	return 0
}
# ==== responder seat: charon answers, racoon2 iked initiates ============
# i2i_peer_r_conf <C> <HR> <HI> <name> <peer> — swanctl conn for a charon
# RESPONDER (local_addrs=HR, my id racoon2-matrix; expects initiator id
# r2init-matrix).  PSK hex read from the matrix psk, never printed.
i2i_peer_r_conf() {
	_C=$1 _HR=$2 _HI=$3 _name=$4 _peer=$5
	[ "$_peer" = charon ] || return 0
	I2I_CHARON_R_CONF="$I2I_CHARON_VDIR/r2-${_name}.conf"
	mkdir -p "$I2I_CHARON_VDIR" || return 1
	_pskhex=$(psk_file_hex "$ETC/psk/macos.psk") || { log "FAIL: charon psk hex"; return 1; }
	cat > "$I2I_CHARON_R_CONF" <<EOF
connections {
	$_name {
		version = 2
		rekey_time = 0s
		proposals = ${I2I_PROPOSAL}
		local_addrs = $_HR
		remote_addrs = $_HI
		local {
			id = racoon2-matrix
			auth = psk
		}
		remote {
			id = r2init-matrix
			auth = psk
		}
$(ppk_conn_lines)
		children {
			ch {
				local_ts = $_HR/32
				remote_ts = $_HI/32
				esp_proposals = ${I2I_ESP}
				rekey_time = 0s
			}
		}
	}
}
secrets {
	ike-$_name {
		secret = "0x$_pskhex"
	}
$(ppk_secret_block "$_name")
}
EOF
	return 0
}

# i2i_peer_r_start <D> <NSR> <peer> <name> — spawn the charon RESPONDER in
# the responder netns (stderr to $D/charon-resp.log).  iked spawn stays in
# the kind.  charon is passive; it is loaded, never initiated.
i2i_peer_r_start() {
	_D=$1 _NSR=$2 _peer=$3 _name=$4
	[ "$_peer" = charon ] || return 0
	( ip netns exec "$_NSR" "$I2I_CHARON_BIN" --debug-ike 3 --debug-knl 1 \
	    --debug-cfg 2 --debug-mgr 2 --debug-net 1 ) >"$_D/charon-resp.log" 2>&1 &
	sleep 2
	return 0
}

# i2i_peer_r_trigger <D> <NSR> <peer> <name> — LOAD conns only (no
# initiate): the racoon2 initiator drives the exchange via establish-sa.
i2i_peer_r_trigger() {
	_D=$1 _NSR=$2 _peer=$3 _name=$4
	[ "$_peer" = charon ] || return 0
	( ip netns exec "$_NSR" "$I2I_SWANCTL_BIN" --load-all --debug 2 ) >"$_D/swanctl-load-resp.log" 2>&1
	return 0
}

# i2i_peer_r_evidence <D> <peer> — this RESPONDER completed its ADDKE side:
# iked logs round-complete; a charon RESPONDER does NOT emit the initiator-
# seat 'state change: CONNECTING => ESTABLISHED' (it logs CREATED=>
# CONNECTING then finishes via MGR checkin) — instead prove it selected the
# ML-KEM proposal AND verified the peer AUTH (which is IntAuth-chained under
# RFC 9242, so SK(1) matched); the ESP child landing elsewhere in the kind
# is the up= gate.
i2i_peer_r_evidence() {
	_D=$1 _peer=$2
	if [ "$_peer" = charon ]; then
		grep -q 'selected proposal: IKE:.*KE1_ML_KEM_768' "$_D/charon-resp.log" 2>/dev/null &&
		grep -q "authentication of 'r2init-matrix' with pre-shared key successful" "$_D/charon-resp.log" 2>/dev/null
		return $?
	fi
	grep -q 'IKE_INTERMEDIATE ADDKE round complete' "$_D/resp-iked.log" 2>/dev/null
}

# i2i_peer_r_diag <D> <peer> — charon RESPONDER-side failure tail.
i2i_peer_r_diag() {
	_D=$1 _peer=$2
	[ "$_peer" = charon ] || return 0
	grep -E 'selected proposal|KE1_ML_KEM_768|state change|not acceptable|no proposal|received proposals' \
		"$_D/charon-resp.log" 2>/dev/null | tail -8
}

# i2i_peer_r_cleanup <peer> <name> — stop the charon RESPONDER, drop its
# swanctl conn file.  iked cleanup stays in the kind.
i2i_peer_r_cleanup() {
	_peer=$1 _name=$2
	[ "$_peer" = charon ] || return 0
	# same no-silent-no-op guard as the initiator-seat cleanup.
	command -v killall >/dev/null 2>&1 || { log "FAIL: no killall (psmisc) — charon cleanup would no-op"; return 1; }
	require_procps || return 1
	killall -9 charon 2>/dev/null || true
	rm -f /var/run/charon.pid /var/run/charon.ctl
	rm -f "${I2I_CHARON_R_CONF:-/nonexistent}"
	return 0
}

