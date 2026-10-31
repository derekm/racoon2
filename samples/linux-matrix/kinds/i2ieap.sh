#!/bin/sh
# kinds/i2ieap.sh — EAP remote-access (RFC 7296 s2.16) iked responder vs a
# strongSwan charon INITIATOR, proxying the client's EAP-MSCHAPv2 to a
# netns-local FreeRADIUS clone.
#
# Shape (the production MSCHAPv2 remote-access deployment, per the wiring
# plan's milestone 1): the CLIENT authenticates via EAP-MSCHAPv2 (FreeRADIUS
# terminates it), the RESPONDER authenticates itself with its own RSA
# certificate.  Responder conf: kmp_auth_method { eap; rsasig; } with a
# run-generated server cert (my_public_key) and radius_server/secret_file;
# the responder's FIRST IKE_AUTH response carries IDr + CERT + AUTH +
# EAP-Identity; the client's final non-mutual-MSCHAPv2 MSK-AUTH completes
# the SA.  This is the shape strict charon accepts (it rejects EAP-ONLY /
# RFC 5998 auth with the non-mutual MSCHAPv2 method).
#
# Requires box strongSwan charon (EAP initiator) + FreeRADIUS + a loopback
# to the responder netns's RADIUS port.  gate=box keeps it out of CI.
kind_i2ieap() {
	name=$1
	require_root || return 1
	[ -x "$SBIN/iked" ] || { log "FAIL: no $SBIN/iked"; return 1; }
	[ -f "$ETC/spmd.pwd" ] || { log "FAIL: no $ETC/spmd.pwd"; return 1; }
	# FreeRADIUS: Fedora radiusd + /etc/raddb, Debian freeradius + /etc/freeradius/3.0
	RADCMD=; RADSRC=
	for _c in /usr/sbin/radiusd /usr/sbin/freeradius; do [ -x "$_c" ] && { RADCMD=$_c; break; }; done
	for _d in /etc/raddb /etc/freeradius/3.0; do [ -d "$_d" ] && { RADSRC=$_d; break; }; done
	[ -n "$RADCMD" ] && [ -n "$RADSRC" ] || { log "FAIL: no FreeRADIUS (radiusd/freeradius + raddb)"; return 1; }
	command -v openssl >/dev/null 2>&1 || { log "FAIL: no openssl"; return 1; }
	command -v "$I2I_CHARON_BIN" >/dev/null 2>&1 || { log "FAIL: no charon $I2I_CHARON_BIN"; return 1; }
	command -v "$I2I_SWANCTL_BIN" >/dev/null 2>&1 || { log "FAIL: no $I2I_SWANCTL_BIN"; return 1; }

	row_ns "$name"
	HR=192.0.6.1; HI=192.0.6.2
	rm -rf "$PRIVRES_R" "$D" "$C"; mkdir -p "$PRIVRES_R" "$D" "$C" "$C/certs"

	# --- build server cert (responder's own signing cert), charon-known CA ---
	openssl genrsa -out "$C/certs/ca.key" 2048 2>/dev/null || { log "FAIL: genrsa ca"; return 1; }
	openssl req -new -x509 -key "$C/certs/ca.key" -out "$C/certs/ca.pem" -days 3650 \
		-subj "/CN=r2-eap-test-ca" 2>/dev/null || { log "FAIL: ca self-signed"; return 1; }
	openssl genrsa -out "$C/certs/server.key" 2048 2>/dev/null || { log "FAIL: genrsa server"; return 1; }
	printf "subjectAltName=IP:%s,DNS:racoon2-eap\n" "$HR" > "$C/certs/san.cnf"
	openssl req -new -key "$C/certs/server.key" -out "$C/certs/server.csr" \
		-subj "/CN=racoon2-eap" 2>/dev/null || { log "FAIL: req server"; return 1; }
	openssl x509 -req -in "$C/certs/server.csr" -CA "$C/certs/ca.pem" -CAkey "$C/certs/ca.key" \
		-CAcreateserial -out "$C/certs/server.pem" -days 3650 -sha256 \
		-extfile "$C/certs/san.cnf" 2>/dev/null || { log "FAIL: x509 server"; return 1; }
	# combined cert+key file is what iked's my_pubkey x509pem wants for BOTH
	chmod 644 "$C/certs/server.pem" "$C/certs/server.key"
	SSLENV="SSL_CERT_FILE=$C/certs/ca.pem"

	# EAP-TLS variant (row name *-tls): a client cert is needed for the
	# charon EAP-TLS initiator AND a server cert for FreeRADIUS's TLS EAP
	# module (which uses certdir/server.pem).  Both signed by the same CA.
	I2IEAP_TLS=0
	case $name in *-tls) I2IEAP_TLS=1 ;; esac
	# RFC 4739 variant (row name *-multi): charon authenticates TWICE,
	# round one with its client certificate (pubkey, SAN DNS:eaptest)
	# flagged N(ANOTHER_AUTH_FOLLOWS), round two with EAP-MSCHAPv2.  The
	# responder runs multiple_auth on with cert_validate + ca_file so the
	# round-one signature is checked against the wire cert chain.
	I2IEAP_MULTI=0
	case $name in *-multi) I2IEAP_MULTI=1 ;; esac
	if [ "$I2IEAP_TLS" -eq 1 ] || [ "$I2IEAP_MULTI" -eq 1 ]; then
		# client cert for charon (EAP-TLS client auth).  The EAP identity
		# is the bare FQDN 'eaptest', so the cert must carry a
		# subjectAltName DNS:eaptest — otherwise charon (which matches
		# certs to the requested EAP identity by type: SAN-DNS vs
		# subject-DN) reports "no usable TLS client certificate".
		openssl genrsa -out "$C/certs/client.key" 2048 2>/dev/null || { log "FAIL: genrsa client"; return 1; }
		printf "subjectAltName=DNS:eaptest\n" > "$C/certs/client-san.cnf"
		openssl req -new -key "$C/certs/client.key" -out "$C/certs/client.csr" \
			-subj "/CN=eaptest" 2>/dev/null || { log "FAIL: req client"; return 1; }
		openssl x509 -req -in "$C/certs/client.csr" -CA "$C/certs/ca.pem" -CAkey "$C/certs/ca.key" \
			-CAcreateserial -out "$C/certs/client-cert.pem" -days 3650 -sha256 \
			-extfile "$C/certs/client-san.cnf" 2>/dev/null \
			|| { log "FAIL: x509 client"; return 1; }
		chmod 600 "$C/certs/client.key"
		echo "I2IEAP_TLS=1 (row $name): client (DNS:eaptest SAN) + server cert generated"
	fi

	# --- FreeRADIUS clone (MSCHAPv2) + test account, netns-local ---
	RADD=/tmp/raddb-eap-$name
	rm -rf "$RADD"
	cp -r "$RADSRC" "$RADD" 2>/dev/null || { log "FAIL: cp raddb"; return 1; }
	chmod -R a+rX "$RADD"
	# load a local account and force MSCHAPv2's default EAP type
	sed -i 's/^[[:space:]]*default_eap_type[[:space:]]*=.*/	default_eap_type = mschapv2/' "$RADD/mods-enabled/eap" 2>/dev/null
	# disable ntlm_auth in the clone's mschap module so a local
	# Cleartext-Password account works instead of a winbind/AD lookup
	# (ntlm_auth against unavailable AD returns 0xc0000001 -> Access-Reject)
	sed -i 's|ntlm_auth.*|# ntlm_auth disabled (test local account)|' "$RADD/mods-available/mschap" "$RADD/mods-enabled/mschap" 2>/dev/null
	# ensure a local user
	printf 'eaptest        Cleartext-Password := "eaptest-pass"\n' > "$RADD/users"
	# FreeRADIUS's eap module instantiates the tls submodule at startup
	# even for MSCHAPv2 rows; if its server cert is missing, rlm_eap_tls
	# fails to init and the WHOLE rlm_eap module fails to load, so every
	# EAP request gets Access-Reject and the iked responder sends
	# EAP/FAIL (seen on i2ieap-mschapv2 / i2ieap-multi).  tls-common reads
	# ${certdir}/server.pem (certdir = $RADD/certs); place server
	# cert+key+CA there and pin the key/cert/ca files for every row.
	# 'cp -r /etc/raddb' de-referenced mods-enabled/eap into a regular
	# FILE, so edit THAT (not mods-available) -- radiusd reads
	# mods-enabled/eap.
	mkdir -p "$RADD/certs"
	cp "$C/certs/server.pem" "$RADD/certs/server.pem"
	cp "$C/certs/server.key"  "$RADD/certs/server.key"
	cp "$C/certs/ca.pem"      "$RADD/certs/ca.pem"
	# radiusd drops privileges after bind, so the certs must be
	# world-readable (both for the FreeRADIUS TLS half and the
	# via-loopback RADIUS client).
	chmod 644 "$RADD/certs/server.pem" "$RADD/certs/server.key" "$RADD/certs/ca.pem"
	# tls-common (within mods-enabled/eap): plain key (empty password),
	# certificate = server.pem.  Pin both so the key and cert always pair
	# (Fedora's default private_key_file=$(certdir)/server.key; Debian
	# points certificate_file at snakeoil).
	sed -i 's|^[[:space:]]*private_key_password = .*|private_key_password = ""|' "$RADD/mods-enabled/eap" 2>/dev/null
	sed -i 's|^[[:space:]]*private_key_file = .*|private_key_file = ${certdir}/server.key|' "$RADD/mods-enabled/eap" 2>/dev/null
	sed -i 's|^[[:space:]]*certificate_file = .*|certificate_file = ${certdir}/server.pem|' "$RADD/mods-enabled/eap" 2>/dev/null
	# Point ca_file at the (now present) CA; harmless for MSCHAPv2 (no
	# client cert presented), required for the mutual-TLS variant.
	sed -i 's|^[[:space:]]*#\?[[:space:]]*ca_file = .*|ca_file = ${certdir}/ca.pem|' "$RADD/mods-enabled/eap" 2>/dev/null
	# --- EAP-TLS variant: FreeRADIUS terminates TLS and mutual-auths with
	# the client cert, trusting the shared CA; multi keeps MSCHAPv2 as the
	# round-two EAP (default_eap_type already set to mschapv2 above). ---
	if [ "$I2IEAP_TLS" -eq 1 ]; then
		sed -i 's/^[[:space:]]*default_eap_type[[:space:]]*=.*/	default_eap_type = tls/' "$RADD/mods-enabled/eap" 2>/dev/null
		sed -i 's|^[[:space:]]*#\?[[:space:]]*verify_client = .*|verify_client = yes|' "$RADD/mods-enabled/eap" 2>/dev/null
		echo "EAP-TLS: FreeRADIUS default_eap_type=tls, plain key + cert, ca_file + verify_client=yes (mods-enabled/eap)"
	fi
	# RADIUS shared secret: r2-eap-test-secret
	printf 'racoon2-eap-test-secret-0123456789abcdef\n' > "$C/radius-secret"
	cp "$C/radius-secret" /tmp/eap-${name}-rsec
	chmod 600 /tmp/eap-${name}-rsec
	# the RADIUS client (the iked responder, 127.0.0.1 in the responder
	# netns) must share that same secret with the clone, else FreeRADIUS
	# drops every Access-Request ('Shared secret is incorrect').  The stock
	# clients.conf uses the prod secret, so overwrite it for this clone.
	cat > "$RADD/clients.conf" <<EOF
client localhost {
	ipaddr = 127.0.0.1
	secret = racoon2-eap-test-secret-0123456789abcdef
	shortname = r2eap
}
EOF
	chmod 640 "$RADD/clients.conf"

	# --- responder.conf: eap + rsasig, my cert, radius on ns loopback ---
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
		my_id fqdn "racoon2-eap";
		peers_id fqdn "eaptest";
		peers_ipaddr "$HI";
		kmp_enc_alg { aes256_cbc; };
		kmp_prf_alg { hmac_sha2_256; };
		kmp_hash_alg { hmac_sha2_256; };
		kmp_dh_group { modp2048; };
		kmp_auth_method { eap; rsasig; };
$( [ "$I2IEAP_MULTI" -eq 1 ] && printf '\t\tmultiple_auth on;\n\t\tcert_validate on;\n\t\tca_file "%s";\n' "$C/certs/ca.pem" )
		my_public_key x509pem "$C/certs/server.pem" "$C/certs/server.key";
		radius_server "127.0.0.1";
		radius_port 1812;
		radius_secret_file "/tmp/eap-${name}-rsec";
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
	ipsec_sa_lifetime_time 300 sec;
	sa_index esp_e;
};
sa esp_e {
	sa_protocol esp;
	esp_enc_alg { aes_gcm; };
	esp_auth_alg { non_auth; };
};
EOF

	# --- charon initiator swanctl conn (EAP-MSCHAPv2, responder cert via CA) ---
	CONN=$I2I_CHARON_VDIR/r2-${name}.conf
	mkdir -p "$(dirname "$CONN")"
	mkdir -p "${I2I_CHARON_VDIR%/conf.d}/x509ca" "${I2I_CHARON_VDIR%/conf.d}/x509"
	# clear stale conns from prior EAP runs so charon only sees this row's
	# connection (a leftover conn can hijack --initiate --child).  Drop ALL
	# conn files, not just r2-*: earlier probes may have written e.g.
	# etls.conf with a conn named rtls.
	rm -f "$I2I_CHARON_VDIR"/*.conf 2>/dev/null || true
	cp "$C/certs/ca.pem" "${I2I_CHARON_VDIR%/conf.d}"/x509ca/r2-${name}-ca.pem
	chmod 644 "${I2I_CHARON_VDIR%/conf.d}"/x509ca/r2-${name}-ca.pem
	# EAP-TLS initiator credential: install the client cert (x509/,
	# auto-loaded) and its matching PRIVATE KEY (private/, auto-loaded) —
	# charon needs both to present the cert as its EAP-TLS identity.
	# Drop STALE client creds for this row first (a leftover mismatched
	# cert/key pair makes charon report "no usable TLS client cert").
	if [ "$I2IEAP_TLS" -eq 1 ] || [ "$I2IEAP_MULTI" -eq 1 ]; then
		mkdir -p "${I2I_CHARON_VDIR%/conf.d}"/private
		rm -f "${I2I_CHARON_VDIR%/conf.d}"/x509/r2-${name}-client*.pem \
		      "${I2I_CHARON_VDIR%/conf.d}"/private/r2-${name}-client*.pem 2>/dev/null || true
		cp "$C/certs/client-cert.pem" "${I2I_CHARON_VDIR%/conf.d}"/x509/r2-${name}-client-cert.pem
		cp "$C/certs/client.key" "${I2I_CHARON_VDIR%/conf.d}"/private/r2-${name}-client-key.pem
		chmod 644 "${I2I_CHARON_VDIR%/conf.d}"/x509/r2-${name}-client-cert.pem
		chmod 600 "${I2I_CHARON_VDIR%/conf.d}"/private/r2-${name}-client-key.pem
	fi
	# EAP-TLS variant uses directly the eap-tls auth with a client cert;
	# `certs=` pins the cert (charon auto-pairs the matching private key
	# from the loaded key store for EAP-TLS mutual auth).  There is NO
	# `key=` option in a swanctl local{} block (invalid -> config
	# discarded).
	I2IEAP_LOCAL2=
	I2IEAP_CONNOPT=
	if [ "$I2IEAP_MULTI" -eq 1 ]; then
		# round one: client cert; round two (local-2): EAP-MSCHAPv2
		I2IEAP_LOCALAUTH='auth = pubkey
		certs = r2-'"$name"'-client-cert.pem'
		# iked sends no CERTREQ in IKE_SA_INIT, so charon would omit
		# its CERT (send_cert=ifasked) and round one could not verify
		I2IEAP_CONNOPT='send_cert = always'
		I2IEAP_LOCAL2='local-2 {
			auth = eap
			eap_id = eaptest
			id = eaptest
		}'
	elif [ "$I2IEAP_TLS" -eq 1 ]; then
		I2IEAP_LOCALAUTH='auth = eap-tls
		certs = r2-'"$name"'-client-cert.pem'
	else
		I2IEAP_LOCALAUTH='auth = eap
		eap_id = eaptest
		# present an IKEv2 IDi that matches the responder's
		# peers_id (fqdn "eaptest"); otherwise charon sends its IP
		# (IDT_IPADDR) and the responder's peers_id check (RFC
		# 7296 s2.16 enforcement) correctly refuses it.  A bare
		# 'eaptest' (no '@') is inferred as an FQDN-type identity
		# by strongSwan, matching peers_id fqdn.'
	fi
	cat > "$C/eap-conn.conf" <<EOF
connections {
	r2eap {
		version = 2
		proposals = aes256-sha256-modp2048
		local_addrs = $HI
		remote_addrs = $HR
		$I2IEAP_CONNOPT
		local {
			$I2IEAP_LOCALAUTH
			id = eaptest
		}
		$I2IEAP_LOCAL2
		remote {
			auth = pubkey
			id = racoon2-eap
		}
		children {
			ch {
				local_ts = $HI/32
				remote_ts = $HR/32
				esp_proposals = aes128gcm16
				rekey_time = 0s
			}
		}
	}
}
secrets {
	eap-eaptest {
		id = eaptest
		secret = "eaptest-pass"
	}
}
EOF
	cp "$C/eap-conn.conf" "$CONN"; chmod 600 "$CONN"

	# --- cleanup + netns + veth + UDP-allow ---
	pkill -9 -f "$C/" 2>/dev/null || true
	pkill -9 -f -- "-d $RADD" 2>/dev/null || true
	rm -f "$SPMIF_R" "$SPMIF_I" "$SOCK_R" "$SOCK_I"
	ip netns del "$NSR" 2>/dev/null || true
	ip netns del "$NSI" 2>/dev/null || true
	ip netns add "$NSR"; ip netns add "$NSI"
	ip netns exec "$NSR" ip link set lo up
	ip netns exec "$NSI" ip link set lo up
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

	# --- FreeRADIUS inside responder netns (loopback 1812) ---
	( ip netns exec "$NSR" "$RADCMD" -d "$RADD" -X ) >"$D/radiusd.log" 2>&1 &
	RADPID=$!
	i=0; until ip netns exec "$NSR" ss -lun 2>/dev/null | grep -q ':1812' || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
	# Early gate: a FreeRADIUS module that fails to load (e.g. rlm_eap
	# without its server cert) leaves no :1812 listener, and every later
	# gate would only report a vague "not ESTABLISHED".  Name the cause
	# and stop the row here instead.
	if ! ip netns exec "$NSR" ss -lun 2>/dev/null | grep -q ':1812' ||
	   grep -Eq 'Failed to load module|Instantiation failed|Failed instantiating|Errors (reading|initializing)' "$D/radiusd.log"; then
		log "FAIL: FreeRADIUS did not come up: $(grep -Em3 'Failed|Instantiation|Errors|rror' "$D/radiusd.log" | tr '\n' ' ')"
		pkill -9 -f -- "-d $RADD" 2>/dev/null || true
		for _ns in "$NSR" "$NSI"; do ip netns del "$_ns" 2>/dev/null || true; done
		return 1
	fi

	# --- responder spmd + iked ---
	( ip netns exec "$NSR" env "$SSLENV" "$SBIN/spmd" -F -f "$C/responder.conf" ) >"$D/resp-spmd.log" 2>&1 &
	RSPMD=$!
	i=0; until [ -S "$SPMIF_R" ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
	# Honor the row's workers cell: with a numeric R2_WORKERS the iked must
	# run the crypto worker pool so the EAP RADIUS round executes on a worker
	# thread instead of inlining into the select loop (a multi-second RADIUS
	# round on a real link would otherwise block every other SA). The gate
	# below asserts the 'crypto workers: N' startup line when N>0. The sock
	# and resume dir are passed unconditionally; only the workers var is
	# conditional (mirrors ikev2.sh so an empty cell cannot drop the other
	# env).
	_WK=""
	[ -n "${R2_WORKERS-}" ] && _WK="RACOON2_CRYPTO_WORKERS=$R2_WORKERS"
	( ip netns exec "$NSR" env "$SSLENV" RACOON2_ADMIN_SOCK="$SOCK_R" \
	    RACOON2_RESUME_DIR="$PRIVRES_R" $_WK \
	    "$SBIN/iked" -F -f "$C/responder.conf" -D 0x0003 -l "$D/resp-iked.log" ) >"$D/resp-iked.out" 2>&1 &
	IKE_RPID=$!
	sleep 2

	# --- charon initiator in NSI ---
	# stale global charon pidfile (from a prior run) blocks the in-netns
	# charon: 'charon already running (...pid exists)' then it exits and the
	# later swanctl --initiate gets 'Connection refused'.  Clear it first.
	i2i_charon_kill
	i2i_charon_run "$NSI" "$D/charon-init.log"
	sleep 2
	ip netns exec "$NSI" "$I2I_SWANCTL_BIN" --load-all --debug 2 >"$D/swanctl-load.log" 2>&1
	ip netns exec "$NSI" "$I2I_SWANCTL_BIN" --initiate --child ch --debug 2 >"$D/swanctl-init.log" 2>&1 || true

	# --- gate: charon ESTABLISHED + iked ESTABLISHED + MSK + ESP child ---
	up=0
	i=0
	while [ "$i" -lt 40 ]; do
		ce=$(grep -c "CONNECTING => ESTABLISHED" "$D/charon-init.log" 2>/dev/null)
		se=$(grep -c "RES_IKE_AUTH_RCVD -> ESTABLISHED" "$D/resp-iked.log" 2>/dev/null)
		if [ "${ce:-0}" -ge 1 ] && [ "${se:-0}" -ge 1 ]; then
			log "EAP ESTABLISHED: charon '$ce' iked '$se' after ${i}s"
			up=1
			break
		fi
		i=$((i+1)); sleep 1
	done
	[ "$up" -eq 1 ] && i2i_dataplane "$NSI" "$HR" "$name"

	# not "fail": that is run.sh's global row counter (this kind runs
	# in the runner's shell), and clobbering it hid FAIL rows from the
	# summary and exit status.
	efail=0
	if [ "${up:-0}" -ne 1 ]; then
		log "FAIL: not ESTABLISHED (charon=${ce:-0} iked=${se:-0})"
		efail=1
	fi
	# MSK + EAP-Success on the responder (the milestone-1 core).  charon
	# logs the EAP success with the method name (MSCHAPv2 vs TLS), so
	# match either "with EAP successful" or the EAP-TLS form.
	msk=$(grep -c "MSK stored (l=64)" "$D/resp-iked.log" 2>/dev/null)
	auth=$(grep -cE "with (EAP|EAP-TLS) successful" "$D/charon-init.log" 2>/dev/null)
	[ "${msk:-0}" -ge 1 ] && [ "${auth:-0}" -ge 1 ] || {
		log "FAIL: MSK/AUTH evidence missing (msk=${msk:-0} auth=${auth:-0})"
		efail=1
	}
	# ESP child up proves keymat matched
	re=$(ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -c 'proto esp')
	if [ "${re:-0}" -lt 2 ]; then
		log "FAIL: responder ESP states <2 ($re)"
		efail=1
	fi
	# Pool-enabled proof: with a numeric workers cell the daemon must have
	# started its crypto worker pool (non-inline EAP round). This is what
	# closes the "EAP blocks the select loop" gate.
	if [ -n "${R2_WORKERS:-}" ] && [ "${R2_WORKERS:-0}" -gt 0 ]; then
		if ! grep -q "crypto workers: $R2_WORKERS" "$D/resp-iked.log"; then
			log "FAIL: responder iked did not start crypto workers=$R2_WORKERS (EAP round would block the loop)"
			efail=1
		elif grep -q "crypto workers: 0" "$D/resp-iked.log"; then
			log "FAIL: responder iked fell back to workers=0"
			efail=1
		else
			log "EAP pooled: responder iked crypto workers=$R2_WORKERS (non-inline RADIUS round)"
		fi
	fi

	if [ "$I2IEAP_MULTI" -eq 1 ]; then
		# RFC 4739 evidence on both sides: iked ran the two rounds,
		# charon authenticated with its key (round one) AND with EAP
		# (round two), and the responder advertised 16404
		grep -q "multiple auth: first round verified" "$D/resp-iked.log" || {
			log "FAIL: iked did not run a multiple-auth first round"; efail=1; }
		grep -q "advertising MULTIPLE_AUTH_SUPPORTED" "$D/resp-iked.log" || {
			log "FAIL: iked did not advertise MULTIPLE_AUTH_SUPPORTED"; efail=1; }
		grep -qE "authentication of 'eaptest' \(myself\) with (RSA|ECDSA|RSASSA)" "$D/charon-init.log" || {
			log "FAIL: charon round one (pubkey) not seen"; efail=1; }
		grep -q "ANOTHER_AUTH_FOLLOWS\|N(AUTH_FOLLOWS)" "$D/charon-init.log" || {
			log "FAIL: charon did not send ANOTHER_AUTH_FOLLOWS"; efail=1; }
	fi
	method=EAP-MSCHAPv2; [ "$I2IEAP_TLS" -eq 1 ] && method=EAP-TLS
	[ "$I2IEAP_MULTI" -eq 1 ] && method="pubkey+EAP-MSCHAPv2 (RFC 4739)"
	[ "$efail" -eq 0 ] && log "PASS $name ($method + responder cert -> ESTABLISHED, ESP up)"
	# cleanup on EVERY exit path (this row's daemons/sockets/netns): the
	# old kind only pkilled at START, so a finished row left its daemons
	# running as live orphan load for the whole sweep.
	pkill -9 -f "$C/" 2>/dev/null || true              # row's iked/spmd (-f $C/conf)
	pkill -9 -f -- "-d $RADD" 2>/dev/null || true # row's radiusd
	i2i_charon_kill                                    # row's charon (argv carries the charon conf/socket paths, not $C/)
	for _ns in "$NSR" "$NSI"; do ip netns del "$_ns" 2>/dev/null || true; done
	return "$efail"
}
