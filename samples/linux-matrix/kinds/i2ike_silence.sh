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
kind_i2ike_silence() {
	local NSR=r2i2ikesilr NSI=r2i2ikesili
	local VR=i2ikesil-r VI=i2ikesil-i
	local HR=192.0.8.1 HI=192.0.8.2
	local C=/tmp/r2-i2ikesil-conf
	local D=/tmp/r2-i2ikesil
	local pass_ok=0
	local attempt
	local attempts=1
	command -v tcpdump >/dev/null 2>&1 || { log "FAIL: tcpdump missing"; return 1; }
	require_root || return 1
	require_procps || return 1
	ip link del "$VR" 2>/dev/null || true
	ip link del "$VI" 2>/dev/null || true
	ip netns del "$NSR" 2>/dev/null || true
	ip netns del "$NSI" 2>/dev/null || true
	ip netns add "$NSR"
	ip netns add "$NSI"
	ip link add "$VR" type veth peer name "$VI"
	ip link set "$VR" netns "$NSR"
	ip link set "$VI" netns "$NSI"
	ip netns exec "$NSR" ip addr add "$HR/24" dev "$VR"
	ip netns exec "$NSI" ip addr add "$HI/24" dev "$VI"
	ip netns exec "$NSR" ip link set "$VR" up
	ip netns exec "$NSI" ip link set "$VI" up
	ip netns exec "$NSR" ip link set lo up
	ip netns exec "$NSI" ip link set lo up
	mkdir -p "$C/psk" "$D"
	cp "$SAMPLE/psk/macos.psk" "$C/psk/macos.psk"
	cat > "$C/racoon2.conf" <<EOF
interfaces { vnet0; };
resolver { nameserver 127.0.0.1; };
include "$C/psk/macos.psk";
EOF
	cat > "$C/responder.conf" <<EOF
interface { vnet0 { $HR/24; }; };
remote anonymous {
	acceptable_kmp { ikev2; };
	passive on;
	ikev2 {
		kmp_sa_lifetime_time 3600;
		kmp_sa_nego_time_limit 60;
		kmp_sa_grace_period 120;
		ipsec_sa_nego_time_limit 60;
		logmode ikev2;
		log_level debug;
		dpd on;
		dpd_delay 60;
		my_id_type asn1dn;
		selector_index from_id;
		selector_order address_index;
		nonce_size 32;
		max_retry_to_send 5;
		kmp_enc_alg aes256_cbc;
		kmp_prf_alg hmac_sha2_256;
		kmp_hash_alg hmac_sha2_256;
		kmp_dh_group 2048modp;
		kmp_auth_method psk;
		peers_identifier asn1dn;
		ipsec_sa_lifetime_time 3600;
		ipsec_sa_lifetime_soft_time 3000;
		ipsec_sa_lifetime_soft_byte 1000000000;
		ipsec_sa_lifetime_byte 2000000000;
		esp_enc_alg aes256_cbc;
		esp_auth_alg hmac_sha2_256;
	};
};
selector default {
	direction outbound;
	policy ipsec ipsec esp;
	remote_index from_id;
};
EOF
	cat > "$C/initiator.conf" <<EOF
interface { vnet0 { $HI/24; }; };
remote $HR {
	acceptable_kmp { ikev2; };
	ikev2 {
		kmp_sa_lifetime_time 3600;
		kmp_sa_nego_time_limit 60;
		kmp_sa_grace_period 120;
		ipsec_sa_nego_time_limit 60;
		logmode ikev2;
		log_level debug;
		dpd on;
		dpd_delay 60;
		my_id_type asn1dn;
		selector_index from_id;
		selector_order address_index;
		nonce_size 32;
		max_retry_to_send 5;
		kmp_enc_alg aes256_cbc;
		kmp_prf_alg hmac_sha2_256;
		kmp_hash_alg hmac_sha2_256;
		kmp_dh_group 2048modp;
		kmp_auth_method psk;
		peers_identifier asn1dn;
		ipsec_sa_lifetime_time 3600;
		ipsec_sa_lifetime_soft_time 3000;
		ipsec_sa_lifetime_soft_byte 1000000000;
		ipsec_sa_lifetime_byte 2000000000;
		esp_enc_alg aes256_cbc;
		esp_auth_alg hmac_sha2_256;
	};
};
selector default {
	direction outbound;
	policy ipsec ipsec esp;
	remote_index from_id;
};
EOF
	for attempt in $(seq 1 "$attempts"); do
		ip netns exec "$NSR" ip xfrm state flush 2>/dev/null || true
		ip netns exec "$NSI" ip xfrm state flush 2>/dev/null || true
		ip netns exec "$NSR" ip xfrm policy flush 2>/dev/null || true
		ip netns exec "$NSI" ip xfrm policy flush 2>/dev/null || true
		pkill -f "$C/" 2>/dev/null || true
		sleep 1
		: > "$D/resp-iked.log"
		: > "$D/init-iked.log"
		rm -f "$D/live.pcap" "$D/after.pcap"
		ip netns exec "$NSR" "$IKED" -f "$C/racoon2.conf" -f "$C/responder.conf" -D 0x0001 > "$D/resp-iked.log" 2>&1 &
		ip netns exec "$NSI" "$IKED" -f "$C/racoon2.conf" -f "$C/initiator.conf" -D 0x0001 > "$D/init-iked.log" 2>&1 &
		sleep 1
		ip netns exec "$NSR" "$SPMDCTL" establish-sa ipsec $HI/32 $HR/32 esp || true
		local up=0 i
		for i in $(seq 1 45); do
			if ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -q 'proto esp'; then
				up=1
				break
			fi
			sleep 1
		done
		[ "$up" -eq 1 ] || { log "FAIL: child not up (silence)"; continue; }
		ip netns exec "$NSR" tcpdump -ni "$VR" -w "$D/live.pcap" 'udp port 500 or udp port 4500' >/dev/null 2>&1 &
		# Nine dpd_delay intervals.  First poll is one interval after
		# ESTABLISHED, so 9*60+20 covers nine exchanges without shortening
		# dpd_delay.
		sleep 560
		pkill -f "$D/live.pcap" 2>/dev/null || true
		sleep 1
		local from_i from_r
		from_i=$(tcpdump -nn -r "$D/live.pcap" "src $HI" 2>/dev/null | wc -l | tr -d ' ')
		from_r=$(tcpdump -nn -r "$D/live.pcap" "src $HR" 2>/dev/null | wc -l | tr -d ' ')
		log "silence live-window: initiator datagrams=${from_i:-0} responder datagrams=${from_r:-0}"
		if [ "${from_i:-0}" -lt 9 ] || [ "${from_r:-0}" -lt 9 ]; then
			log "FAIL: fewer than 9 DPD-window datagrams each way"
			continue
		fi
		local u0 x0 c0
		u0=$(grep -c 'dropping unordered' "$D/resp-iked.log" 2>/dev/null || true)
		x0=$(grep -c 'unexpected response' "$D/resp-iked.log" 2>/dev/null || true)
		c0=$(grep -c 'CREATE_CHILD' "$D/resp-iked.log" 2>/dev/null || true)
		ip netns exec "$NSR" tcpdump -ni "$VR" -w "$D/after.pcap" 'udp port 500 or udp port 4500' >/dev/null 2>&1 &
		# Kill only the initiator.  It sends nothing after this.
		pkill -f "$C/initiator.conf" 2>/dev/null || true
		# Ladder 1+2+4+8+16+32+64 = 127s.  150s covers the abort log.
		sleep 150
		pkill -f "$D/after.pcap" 2>/dev/null || true
		sleep 1
		local after
		after=$(tcpdump -nn -r "$D/after.pcap" "src $HI" 2>/dev/null | wc -l | tr -d ' ')
		local u1 x1 c1 abt exc
		u1=$(grep -c 'dropping unordered' "$D/resp-iked.log" 2>/dev/null || true)
		x1=$(grep -c 'unexpected response' "$D/resp-iked.log" 2>/dev/null || true)
		c1=$(grep -c 'CREATE_CHILD' "$D/resp-iked.log" 2>/dev/null || true)
		abt=$(grep -c 'aborting ike_sa err=110' "$D/resp-iked.log" 2>/dev/null || true)
		exc=$(grep -c 'retransmission count exceeded' "$D/resp-iked.log" 2>/dev/null || true)
		log "silence after-kill: inbound-from-initiator=${after:-0} abort=${abt:-0} exceeded=${exc:-0} unordered $u0->$u1 unexpected $x0->$x1 CREATE_CHILD $c0->$c1"
		if [ "${after:-0}" -eq 0 ] && [ "${abt:-0}" -ge 1 ] && [ "${exc:-0}" -ge 1 ] \
			&& [ "${u1:-0}" -eq "${u0:-0}" ] && [ "${x1:-0}" -eq "${x0:-0}" ] \
			&& [ "${c1:-0}" -eq "${c0:-0}" ]; then
			pass_ok=1
			log "SILENCE-TEST: initiator silence aborted by the retransmit ladder (err=110), no unordered/unexpected/CREATE_CHILD growth, zero inbound UDP after the kill"
			break
		fi
		log "FAIL: silence row did not match the ladder abort (attempt $attempt)"
	done
	pkill -f "$C/" 2>/dev/null || true
	sleep 1
	ip netns del "$NSR" 2>/dev/null || true
	ip netns del "$NSI" 2>/dev/null || true
	ip link del "$VR" 2>/dev/null || true
	ip link del "$VI" 2>/dev/null || true
	[ "$pass_ok" -eq 1 ]
}
