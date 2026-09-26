# kinds/i2ike_silence.sh — silence is the retransmit ladder, not a mishandle.
# iked<->iked on 192.0.8.x, own netns.  Both child lifetimes are 3600s so
# neither side rekeys.  dpd_delay stays 60 (do not shorten it to make the
# row faster).  After ESTABLISHED, both sides exchange DPD for nine
# intervals.  Then the initiator is killed and sends nothing.  The
# responder must abort with retransmission-count-exceeded / err=110, and
# the journal must not grow dropping-unordered, unexpected-response, or
# CREATE_CHILD during that silence.  A capture on the responder veth must
# show zero datagrams from the initiator after the kill.
# Not a NAT-D row: these peers are not behind NAT, so there is no NAT-D
# INFORMATIONAL to reproduce.  Not in the CI default (nine 60s intervals).
# Classical ESP, not ADDKE: this row is about the DPD ladder.
kind_i2ike_silence() {
	name=$1
	require_root || return 1
	require_procps || return 1
	command -v tcpdump >/dev/null 2>&1 || { log "FAIL: tcpdump missing"; return 1; }
	[ -x "$SBIN/iked" ] || { log "FAIL: no $SBIN/iked"; return 1; }
	[ -f "$ETC/spmd.pwd" ] || { log "FAIL: no $ETC/spmd.pwd"; return 1; }
	[ -f "$ETC/psk/macos.psk" ] || { log "FAIL: no $ETC/psk/macos.psk"; return 1; }

	NSR=i2ikesil-r; NSI=i2ikesil-i; VR=i2vsilr; VI=i2vsili
	HR=192.0.8.1; HI=192.0.8.2
	PRIVRES_R=/tmp/r2-i2ikesil-resume-r; PRIVRES_I=/tmp/r2-i2ikesil-resume-i
	D=/tmp/r2-i2ikesil; C=/tmp/r2-i2ikesil-conf
	rm -rf "$PRIVRES_R" "$PRIVRES_I" "$D" "$C"
	mkdir -p "$PRIVRES_R" "$PRIVRES_I" "$D" "$C"

	cat > "$C/responder.conf" <<EOF
interface {
	ike { "$HR"; };
	spmd { unix "/tmp/spmif-i2ikesil-r"; };
	spmd_password "$ETC/spmd.pwd";
};
resolver { resolver off; };
remote matrix_resp {
	acceptable_kmp { ikev2; };
	ikev2 {
		passive on;
		my_id fqdn "racoon2-matrix";
		peers_id fqdn "r2init-matrix";
		peers_ipaddr "$HI";
		kmp_enc_alg { aes256_cbc; };
		kmp_prf_alg { hmac_sha2_256; };
		kmp_hash_alg { hmac_sha2_256; };
		kmp_dh_group { ecp256; };
		kmp_auth_method { psk; };
		pre_shared_key "$ETC/psk/macos.psk";
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
	esp_enc_alg { aes_gcm; };
	esp_auth_alg { non_auth; };
};
EOF
	cat > "$C/initiator.conf" <<EOF
interface {
	ike { "$HI"; };
	spmd { unix "/tmp/spmif-i2ikesil-i"; };
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
		kmp_enc_alg { aes256_cbc; };
		kmp_prf_alg { hmac_sha2_256; };
		kmp_hash_alg { hmac_sha2_256; };
		kmp_dh_group { ecp256; };
		kmp_auth_method { psk; };
		pre_shared_key "$ETC/psk/macos.psk";
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
	ipsec_sa_lifetime_time 3600 sec;
	sa_index esp_e;
};
sa esp_e {
	sa_protocol esp;
	esp_enc_alg { aes_gcm; };
	esp_auth_alg { non_auth; };
};
EOF

	pass_ok=0
	pkill -9 -f "$C/" 2>/dev/null || true
	rm -f /tmp/spmif-i2ikesil-r /tmp/spmif-i2ikesil-i \
	      /tmp/iked.sock-i2ikesil-r /tmp/iked.sock-i2ikesil-i
	rm -rf "$PRIVRES_R" "$PRIVRES_I"
	mkdir -p "$PRIVRES_R" "$PRIVRES_I"
	: >"$D/resp-iked.log"
	: >"$D/init-iked.log"

	for NS in "$NSR" "$NSI"; do
		ip netns del "$NS" 2>/dev/null || true
		ip netns add "$NS"
		ip netns exec "$NS" ip link set lo up
	done
	ip link del "$VR" 2>/dev/null || true
	ip link del "$VI" 2>/dev/null || true
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
	i=0; until [ -S /tmp/spmif-i2ikesil-r ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
	( ip netns exec "$NSR" env RACOON2_ADMIN_SOCK=/tmp/iked.sock-i2ikesil-r RACOON2_RESUME_DIR="$PRIVRES_R" \
	    "$SBIN/iked" -F -f "$C/responder.conf" -D 0x0001 -l "$D/resp-iked.log" ) >"$D/resp-iked.out" 2>&1 &

	( ip netns exec "$NSI" "$SBIN/spmd" -F -f "$C/initiator.conf" ) >"$D/init-spmd.log" 2>&1 &
	i=0; until [ -S /tmp/spmif-i2ikesil-i ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
	( ip netns exec "$NSI" env RACOON2_ADMIN_SOCK=/tmp/iked.sock-i2ikesil-i RACOON2_RESUME_DIR="$PRIVRES_I" \
	    "$SBIN/iked" -F -f "$C/initiator.conf" -D 0x0001 -l "$D/init-iked.log" ) >"$D/init-iked.out" 2>&1 &

	sleep 2
	"$SBIN/ikedctl" -s /tmp/iked.sock-i2ikesil-i establish-sa isakmp inet "$HI" "$HR" sel_out >/dev/null 2>&1 || true

	up=0
	i=0
	while [ "$i" -lt 45 ]; do
		re=$(ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -c 'proto esp' || true)
		ie=$(ip netns exec "$NSI" ip xfrm state 2>/dev/null | grep -c 'proto esp' || true)
		if [ "${re:-0}" -ge 2 ] && [ "${ie:-0}" -ge 2 ]; then
			log "silence child UP: responder esp=$re initiator esp=$ie after ${i}s"
			up=1
			break
		fi
		i=$((i+1))
		sleep 1
	done
	if [ "$up" -ne 1 ]; then
		log "FAIL: child not up (silence)"
	else
		ip netns exec "$NSR" tcpdump -ni "$VR" -w "$D/live.pcap" 'udp port 500 or udp port 4500' >/dev/null 2>&1 &
		# Nine dpd_delay intervals.  First poll is one interval after
		# ESTABLISHED, so 9*60+20 covers nine exchanges without shortening
		# dpd_delay.
		sleep 560
		pkill -f "$D/live.pcap" 2>/dev/null || true
		sleep 1
		from_i=$(tcpdump -nn -r "$D/live.pcap" "src $HI" 2>/dev/null | wc -l | tr -d ' ')
		from_r=$(tcpdump -nn -r "$D/live.pcap" "src $HR" 2>/dev/null | wc -l | tr -d ' ')
		log "silence live-window: initiator datagrams=${from_i:-0} responder datagrams=${from_r:-0}"
		if [ "${from_i:-0}" -lt 9 ] || [ "${from_r:-0}" -lt 9 ]; then
			log "FAIL: fewer than 9 DPD-window datagrams each way"
		else
			u0=$(grep -c 'dropping unordered' "$D/resp-iked.log" 2>/dev/null || true)
			x0=$(grep -c 'unexpected response' "$D/resp-iked.log" 2>/dev/null || true)
			c0=$(grep -c 'CREATE_CHILD' "$D/resp-iked.log" 2>/dev/null || true)
			ip netns exec "$NSR" tcpdump -ni "$VR" -w "$D/after.pcap" 'udp port 500 or udp port 4500' >/dev/null 2>&1 &
			# Kill only the initiator.  It sends nothing after this.
			pkill -9 -f "$C/initiator.conf" 2>/dev/null || true
			# Ladder: isakmp retransmit_interval[] = 1,2,4,8,16,32,64 with
			# retry_limit = IKEV2_DEFAULT_RETRY 10.  Re-derived from
			# isakmp.c:2213-2215 + 2449-2465: initial send t=0, retransmits
			# at 1,3,7,15,31,63,127,191,255,319, timeout check at t=383
			# (11th timer, retry_count 10 >= limit 10 -> ikev2_timeout).
			# Not 447s/12th: that adds one extra clamped 64s rung.  Worst
			# case is up to dpd_delay (60s) to the next poll + 383s = 443s;
			# polling to 600s covers it (first 150s try stopped before
			# even the 64s rung: sends 19:36:49 (+32), row ended 19:37:39).
			i=0
			abt=0
			exc=0
			while [ "$i" -lt 600 ]; do
				abt=$(grep -c 'aborting ike_sa err=110' "$D/resp-iked.log" 2>/dev/null || true)
				exc=$(grep -c 'retransmission count exceeded the limit' "$D/resp-iked.log" 2>/dev/null || true)
				if [ "${abt:-0}" -ge 1 ] || [ "${exc:-0}" -ge 1 ]; then
					break
				fi
				i=$((i+1)); sleep 1
			done
			pkill -f "$D/after.pcap" 2>/dev/null || true
			sleep 1
			after=$(tcpdump -nn -r "$D/after.pcap" "src $HI" 2>/dev/null | wc -l | tr -d ' ')
			u1=$(grep -c 'dropping unordered' "$D/resp-iked.log" 2>/dev/null || true)
			x1=$(grep -c 'unexpected response' "$D/resp-iked.log" 2>/dev/null || true)
			c1=$(grep -c 'CREATE_CHILD' "$D/resp-iked.log" 2>/dev/null || true)
			log "silence after-kill: inbound-from-initiator=${after:-0} abort=${abt:-0} exceeded=${exc:-0} unordered $u0->$u1 unexpected $x0->$x1 CREATE_CHILD $c0->$c1"
			if [ "${after:-0}" -eq 0 ] && [ "${abt:-0}" -ge 1 ] && [ "${exc:-0}" -ge 1 ] \
				&& [ "${u1:-0}" -eq "${u0:-0}" ] && [ "${x1:-0}" -eq "${x0:-0}" ] \
				&& [ "${c1:-0}" -eq "${c0:-0}" ]; then
				pass_ok=1
				log "SILENCE-TEST: initiator silence aborted by the retransmit ladder (err=110), no unordered/unexpected/CREATE_CHILD growth, zero inbound UDP after the kill"
			else
				log "FAIL: silence row did not match the ladder abort"
			fi
		fi
	fi
	pkill -9 -f "$C/" 2>/dev/null || true
	sleep 1
	ip netns del "$NSR" 2>/dev/null || true
	ip netns del "$NSI" 2>/dev/null || true
	ip link del "$VR" 2>/dev/null || true
	ip link del "$VI" 2>/dev/null || true
	[ "$pass_ok" -eq 1 ]
}
