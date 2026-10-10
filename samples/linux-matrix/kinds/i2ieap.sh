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
	command -v /usr/sbin/radiusd >/dev/null 2>&1 || { log "FAIL: no FreeRADIUS (radiusd)"; return 1; }
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

	# --- FreeRADIUS clone (MSCHAPv2) + test account, netns-local ---
	RADCMD=/usr/sbin/radiusd
	RADD=/tmp/raddb-eap-$name
	rm -rf "$RADD"
	cp -r /etc/raddb "$RADD" 2>/dev/null || { log "FAIL: cp raddb"; return 1; }
	chmod -R a+rX "$RADD"
	# load a local account and force MSCHAPv2's default EAP type
	sed -i 's/^[[:space:]]*default_eap_type[[:space:]]*=.*/	default_eap_type = mschapv2/' "$RADD/mods-enabled/eap" 2>/dev/null
	# disable ntlm_auth in the clone's mschap module so a local
	# Cleartext-Password account works instead of a winbind/AD lookup
	# (ntlm_auth against unavailable AD returns 0xc0000001 -> Access-Reject)
	sed -i 's|ntlm_auth.*|# ntlm_auth disabled (test local account)|' "$RADD/mods-available/mschap" "$RADD/mods-enabled/mschap" 2>/dev/null
	# ensure a local user
	printf 'eaptest        Cleartext-Password := "eaptest-pass"\n' > "$RADD/users"
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
	CONN=/etc/strongswan/swanctl/conf.d/r2-${name}.conf
	mkdir -p "$(dirname "$CONN")"
	mkdir -p /etc/strongswan/swanctl/x509ca /etc/strongswan/swanctl/x509
	# clear stale conns from prior EAP runs so charon only sees this row's
	# connection (a leftover conn can hijack --initiate --child).  Drop ALL
	# conn files, not just r2-*: earlier probes may have written e.g.
	# etls.conf with a conn named rtls.
	rm -f /etc/strongswan/swanctl/conf.d/*.conf 2>/dev/null || true
	cp "$C/certs/ca.pem" /etc/strongswan/swanctl/x509ca/r2-${name}-ca.pem
	chmod 644 /etc/strongswan/swanctl/x509ca/r2-${name}-ca.pem
	cat > "$C/eap-conn.conf" <<EOF
connections {
	r2eap {
		version = 2
		proposals = aes256-sha256-modp2048
		local_addrs = $HI
		remote_addrs = $HR
		local {
			auth = eap
			eap_id = eaptest
			# present an IKEv2 IDi that matches the responder's
			# peers_id (fqdn "eaptest"); otherwise charon sends its IP
			# (IDT_IPADDR) and the responder's peers_id check (RFC
			# 7296 s2.16 enforcement) correctly refuses it.  A bare
			# 'eaptest' (no '@') is inferred as an FQDN-type identity
			# by strongSwan, matching peers_id fqdn.
			id = eaptest
		}
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
	pkill -9 -f "radiusd -d $RADD" 2>/dev/null || true
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

	# --- responder spmd + iked ---
	( ip netns exec "$NSR" env "$SSLENV" "$SBIN/spmd" -F -f "$C/responder.conf" ) >"$D/resp-spmd.log" 2>&1 &
	RSPMD=$!
	i=0; until [ -S "$SPMIF_R" ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
	( ip netns exec "$NSR" env "$SSLENV" RACOON2_ADMIN_SOCK="$SOCK_R" RACOON2_RESUME_DIR="$PRIVRES_R" \
	    "$SBIN/iked" -F -f "$C/responder.conf" -D 0x0003 -l "$D/resp-iked.log" ) >"$D/resp-iked.out" 2>&1 &
	IKE_RPID=$!
	sleep 2

	# --- charon initiator in NSI ---
	# stale global charon pidfile (from a prior run) blocks the in-netns
	# charon: 'charon already running (...pid exists)' then it exits and the
	# later swanctl --initiate gets 'Connection refused'.  Clear it first.
	rm -f /run/strongswan/charon.pid /var/run/charon.pid 2>/dev/null || true
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

	fail=0
	if [ "${up:-0}" -ne 1 ]; then
		log "FAIL: not ESTABLISHED (charon=${ce:-0} iked=${se:-0})"
		fail=1
	fi
	# MSK + EAP-Success on the responder (the milestone-1 core)
	msk=$(grep -c "MSK stored (l=64)" "$D/resp-iked.log" 2>/dev/null)
	auth=$(grep -c "authentication of 'racoon2-eap' with EAP successful" "$D/charon-init.log" 2>/dev/null)
	[ "${msk:-0}" -ge 1 ] && [ "${auth:-0}" -ge 1 ] || {
		log "FAIL: MSK/AUTH evidence missing (msk=${msk:-0} auth=${auth:-0})"
		fail=1
	}
	# ESP child up proves keymat matched
	re=$(ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -c 'proto esp')
	if [ "${re:-0}" -lt 2 ]; then
		log "FAIL: responder ESP states <2 ($re)"
		fail=1
	fi

	[ "$fail" -eq 0 ] && log "PASS $name (EAP-MSCHAPv2 + responder cert -> ESTABLISHED, ESP up)"
	return "$fail"
}
