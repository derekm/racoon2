#!/bin/sh
# kinds/i2imobike.sh -- RFC 4555 MOBIKE with iked on BOTH seats: the
# initiator (mobike_initiate on) changes its own address and must send
# UPDATE_SA_ADDRESSES; the responder must move its SAs.
#
# Two netns joined by a veth: responder 192.0.8.1, initiator 192.0.8.2.
# The tunnel's inner selectors are 10.8.8.2 (initiator) and 10.8.8.1
# (responder), on lo, so they do not follow the outer address.  The move:
# add 192.0.8.4 on the initiator, point its route to the responder at that
# source, delete 192.0.8.2 (promote_secondaries on, as on any host that
# keeps a second address when the first goes).
#
#   i2imobike-move     plain move: the initiator's rtnetlink event makes
#                      it send UPDATE_SA_ADDRESSES (INFORMATIONAL from the
#                      new address on the wire), both seats' ESP SAs move to
#                      192.0.8.4, none is left on 192.0.8.2, ICMP flows
#   i2imobike-off      CONTROL, same move with mobike_initiate at its
#                      default (off): no INFORMATIONAL from the new address
#                      and the responder's SA stays on 192.0.8.2.  Proves
#                      the move row does not pass by implicit mobility.
#   i2imobike-natin    the new address is SNATed to 192.0.8.3: the update's
#                      NAT_DETECTION must turn UDP encapsulation ON for both
#                      seats (RFC 4555 s3.5), ICMP flows
#   i2imobike-natout   the old address was SNATed (espinudp gated), the new
#                      one is not: encapsulation must go OFF on both seats
#   i2imobike-return   move, then back to the original address: a second
#                      update, both seats on $HI again
#   i2imobike-flap     move, then 11 back-to-back address flips: converge
#                      on the final address, at most one update per change
#   i2imobike-loss     the only address is removed first (no route at
#                      all): iked keeps running and keeps the SAs, sends
#                      nothing, then moves when the new address appears
#   i2imobike-optout   explicit mobike_initiate off with a pinned
#                      interface ike address: no update, nothing moves
#   i2imobike-pinned   mobike_initiate on, interface ike pinned to the
#                      old address: iked declines (no socket there),
#                      sends nothing, keeps its SAs
#   i2imobike-v6       the plain move over IPv6 (outer and inner)
#   i2imobike-dual     dual-stack initiator (MY_IPV4 + MY_IPV6, an IPv4
#                      address stays on the link): the IPv6 IKE SA moves
#   i2imobike-childrekey / -ikerekey
#                      the move happens while the initiator's
#                      CREATE_CHILD_SA (child / IKE rekey) is in flight
#                      (responder answers held): the rekey completes, the
#                      update follows, everything ends on the new address
#   i2imobike-tcp      RFC 9329 IKE over TCP on both seats (tcp_encap on):
#                      the update leaves over a NEW TCP connection from the
#                      new address (TCP SYN from 192.0.8.4 on the wire), the
#                      responder answers over that stream and moves ESP
#                      (UDP-encapsulated 4500/4500 as for every TCP SA)
#   i2imobike-*-nomig  the same, with both iked forced onto the path for a
#                      kernel without CONFIG_XFRM_MIGRATE (SAs re-created,
#                      policy templates updated); its log line is gated
kind_i2imobike() {
	name=$1
	require_root || return 1
	[ -x "$SBIN/iked" ] || { log "FAIL: no $SBIN/iked"; return 1; }
	[ -f "$ETC/spmd.pwd" ] || { log "FAIL: no $ETC/spmd.pwd"; return 1; }
	command -v iptables >/dev/null 2>&1 || { log "FAIL: no iptables"; return 1; }
	scen=${name#i2imobike-}
	# *-nomig: both iked behave as on a kernel without
	# CONFIG_XFRM_MIGRATE (RACOON2_XFRM_NO_MIGRATE=1), so the user-space
	# re-create fallback runs whatever this kernel has
	NOMIG=
	case $scen in *-nomig) NOMIG=1; scen=${scen%-nomig} ;; esac
	row_ns "$name"
	HR=192.0.8.1; HI=192.0.8.2; HN=192.0.8.3; HM=192.0.8.4
	TS_R=10.8.8.1; TS_I=10.8.8.2
	# v6: the same rows over IPv6 (outer and inner); dual: a dual-stack
	# initiator (an IPv4 address stays on the link, iked listens on both
	# families) whose IPv6 IKE SA moves
	PL=24; HL=32; AF=inet; MYIP=MY_IPV4; NODAD=; V6=
	case $name in i2imobike-v6*|i2imobike-dual*)
		V6=1; PL=64; HL=128; AF=inet6; MYIP=MY_IPV6; NODAD=nodad
		HR=2001:db8:8::1; HI=2001:db8:8::2; HN=2001:db8:8::3; HM=2001:db8:8::4
		TS_R=fd00:8::1; TS_I=fd00:8::2
		case $name in i2imobike-dual*) MYIP="MY_IPV4; MY_IPV6" ;; esac ;;
	esac
	rm -rf "$PRIVRES_R" "$PRIVRES_I" "$D" "$C"; mkdir -p "$PRIVRES_R" "$PRIVRES_I" "$D" "$C"
	printf '%s' racoon2-mobike-matrix-0123456789abcdef >"$C/psk.bin"; chmod 600 "$C/psk.bin"

	MI="mobike_initiate on;"; NAT=; TCP=; PIN=; CHILD_LT_I=; IKE_LT_I=; OLD=$HI; NEW=$HM; I_OUT=$HI
	case $scen in
	move) ;;
	off) MI= ;;
	natin) NAT="nat_traversal on;"; NEW=$HN ;;
	natout) NAT="nat_traversal on;"; OLD=$HN; I_OUT=$HN ;;
	tcp) TCP="tcp_encap on;" ;;
	return|flap|loss|v6|dual) ;;
	childrekey) CHILD_LT_I="ipsec_sa_lifetime_time 20 sec;" ;;
	ikerekey) IKE_LT_I="kmp_sa_lifetime_time 20 sec;" ;;
	optout) MI="mobike_initiate off;"; PIN=1 ;;
	pinned) PIN=1 ;;
	*) log "FAIL: unknown scenario $scen"; return 1 ;;
	esac

	# $1 seat (r|i) $2 my addr $3 peer addr (for peers_ipaddr) $4 my TS $5 peer TS
	mkconf() {
		_pas=on; _extra=; _clt="ipsec_sa_lifetime_time 3600 sec;"
		[ "$1" = i ] && { _pas=off; _extra="$MI $IKE_LT_I"; [ -n "$CHILD_LT_I" ] && _clt=$CHILD_LT_I; }
		_spmif=$SPMIF_R; [ "$1" = i ] && _spmif=$SPMIF_I
		_peer=$3; [ "$1" = r ] && _peer=ANY
		cat >"$C/$1.conf" <<EOF
interface {
	ike { $( [ "$1" = i ] && [ -z "$PIN" ] && echo "$MYIP" || echo "\"$2\"" ); };
	spmd { unix "$_spmif"; };
	spmd_password "$ETC/spmd.pwd";
};
resolver { resolver off; };
remote mb {
	acceptable_kmp { ikev2; };
	ikev2 {
		passive $_pas;
		my_id fqdn "mobike-$1";
		peers_id fqdn "mobike-$( [ "$1" = r ] && echo i || echo r )";
		peers_ipaddr $( [ "$_peer" = ANY ] && echo IP_RW || echo "\"$_peer\"" );
		kmp_enc_alg { aes256_cbc; };
		kmp_prf_alg { hmac_sha2_256; };
		kmp_hash_alg { hmac_sha2_256; };
		kmp_dh_group { modp2048; };
		kmp_auth_method { psk; };
		pre_shared_key "$C/psk.bin";
		$_extra
		$NAT
		$TCP
	};
	selector_index sel_in;
};
selector sel_out { direction outbound; src "$4"; dst "$5"; policy_index pol; };
selector sel_in { direction inbound; dst "$4"; src "$5"; policy_index pol; };
policy pol {
	action auto_ipsec;
	remote_index mb;
	ipsec_mode tunnel;
	ipsec_index { ipsec_e; };
	ipsec_level require;
	peers_sa_ipaddr $( [ "$_peer" = ANY ] && echo IP_RW || echo "\"$_peer\"" );
	my_sa_ipaddr "$2";
};
ipsec ipsec_e { $_clt sa_index esp_e; };
sa esp_e { sa_protocol esp; esp_enc_alg { aes256_cbc; }; esp_auth_alg { hmac_sha2_256; }; };
EOF
	}
	mkconf r "$HR" "$HI" "$TS_R" "$TS_I"
	mkconf i "$HI" "$HR" "$TS_I" "$TS_R"

	pkill -9 -f "$C/" 2>/dev/null || true
	rm -f "$SPMIF_R" "$SPMIF_I" "$SOCK_R" "$SOCK_I"
	for NS in "$NSR" "$NSI"; do
		ip netns del "$NS" 2>/dev/null || true
		ip netns add "$NS"; ip netns exec "$NS" ip link set lo up
	done
	ip link add "$VR" type veth peer name "$VI"
	ip link set "$VR" netns "$NSR"; ip link set "$VI" netns "$NSI"
	ip netns exec "$NSI" sysctl -qw "net.ipv4.conf.$VI.promote_secondaries=1"
	ip netns exec "$NSR" ip addr add "$HR/$PL" dev "$VR" $NODAD; ip netns exec "$NSR" ip link set "$VR" up
	ip netns exec "$NSI" ip addr add "$HI/$PL" dev "$VI" $NODAD; ip netns exec "$NSI" ip link set "$VI" up
	if [ "$scen" = dual ]; then
		# the IPv4 side of the dual-stack link: stays put
		ip netns exec "$NSR" ip addr add 192.0.8.1/24 dev "$VR"
		ip netns exec "$NSI" ip addr add 192.0.8.2/24 dev "$VI"
	fi
	ip netns exec "$NSR" ip addr add "$TS_R/$HL" dev lo
	ip netns exec "$NSI" ip addr add "$TS_I/$HL" dev lo
	ip netns exec "$NSR" ip route add "$TS_I/$HL" dev "$VR" src "$TS_R"
	ip netns exec "$NSI" ip route add "$TS_R/$HL" dev "$VI" src "$TS_I"
	# the NAT's public address sits on the link only to answer ARP; the
	# pinned route source keeps iked's route lookup off it
	if [ -n "$NAT" ]; then
		ip netns exec "$NSI" ip addr add "$HN/$PL" dev "$VI" $NODAD
		ip netns exec "$NSI" ip route replace "$HR/$HL" dev "$VI" src "$HI"
	fi
	[ "$scen" = natout ] && { ip netns exec "$NSI" iptables -t nat -A POSTROUTING -o "$VI" -s "$HI" -p udp -j SNAT --to-source "$HN" ||
		{ log "FAIL: SNAT"; return 1; }; }
	[ "$scen" = natin ] && { ip netns exec "$NSI" iptables -t nat -A POSTROUTING -o "$VI" -s "$HM" -p udp -j SNAT --to-source "$HN" ||
		{ log "FAIL: SNAT"; return 1; }; }

	( ip netns exec "$NSR" tcpdump -l -nn -i "$VR" -w "$D/wire.pcap" "udp port 500 or udp port 4500 or tcp port 4500" ) >"$D/tcpdump.out" 2>&1 &
	DUMP=$!
	for s in r i; do
		_ns=$NSR; _sp=$SPMIF_R; _so=$SOCK_R; _pr=$PRIVRES_R
		[ "$s" = i ] && { _ns=$NSI; _sp=$SPMIF_I; _so=$SOCK_I; _pr=$PRIVRES_I; }
		( ip netns exec "$_ns" "$SBIN/spmd" -F -f "$C/$s.conf" ) >"$D/spmd-$s.log" 2>&1 &
		i=0; until [ -S "$_sp" ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
		( ip netns exec "$_ns" env ${NOMIG:+RACOON2_XFRM_NO_MIGRATE=1} RACOON2_ADMIN_SOCK="$_so" RACOON2_RESUME_DIR="$_pr" \
		    "$SBIN/iked" -F -f "$C/$s.conf" -D 0x0001 -l "$D/iked-$s.log" ) >"$D/iked-$s.out" 2>&1 &
	done
	i=0; until [ -S "$SOCK_I" ] && [ -S "$SOCK_R" ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
	sleep 1
	"$SBIN/ikedctl" -s "$SOCK_I" establish-sa isakmp $AF "$HI" "$HR" sel_out >"$D/establish.txt" 2>&1 || true
	efail=0
	outpol() { ip netns exec "$1" ip xfrm policy 2>/dev/null |
		awk -v h="src $2/$HL dst $3/$HL" '$0 ~ "^"h {m=1; next} /^src /{m=0} m && /dir out/{f=1} END{exit !f}'; }
	up=0; i=0
	while [ "$i" -lt 150 ]; do
		ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -q "^src $HR dst $OLD" &&
		ip netns exec "$NSI" ip xfrm state 2>/dev/null | grep -q "^src $HI dst $HR" &&
		outpol "$NSR" "$TS_R" "$TS_I" && outpol "$NSI" "$TS_I" "$TS_R" && { up=1; break; }
		i=$((i+1)); sleep 0.2
	done
	[ "$up" -eq 1 ] || { log "FAIL: child not up"; efail=1; }
	if [ "$up" -eq 1 ]; then
		grep -q "type MOBIKE_SUPPORTED" "$D/iked-i.log" || { log "FAIL: MOBIKE not negotiated"; efail=1; }
		ip netns exec "$NSI" ping -c3 -i0.3 -W2 -I "$TS_I" "$TS_R" >/dev/null 2>&1 ||
			{ log "FAIL: ICMP before the move"; efail=1; }
		if [ "$scen" = natout ]; then
			ip netns exec "$NSR" ip xfrm state | grep -q 'encap type espinudp' ||
				{ log "FAIL: not UDP-encapsulated behind the initial NAT"; efail=1; }
		fi
		upd0=$(grep -c "UPDATE_SA_ADDRESSES" "$D/iked-r.log")
		if [ "$scen" = loss ]; then
			# interface loss: the only address goes (its routes with
			# it); iked must keep running and keep the SAs, then move
			# once an address comes back
			ip netns exec "$NSI" ip addr del "$HI/$PL" dev "$VI"
			i=0; until grep -q "MOBIKE initiator: no route to the peer" "$D/iked-i.log" || [ "$i" -ge 50 ]; do
				i=$((i+1)); sleep 0.2; done
			grep -q "MOBIKE initiator: no route to the peer" "$D/iked-i.log" ||
				{ log "FAIL: iked never processed the address loss"; efail=1; }
			pgrep -f -- "iked -F -f $C/i.conf" >/dev/null 2>&1 || { log "FAIL: iked (i) died on address loss"; efail=1; }
			ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -q "^src $HR dst $HI\$" ||
				{ log "FAIL: the responder SA changed during the outage"; efail=1; }
			nst=$(ip netns exec "$NSI" ip xfrm state 2>/dev/null | grep -c "^src")
			[ "$nst" -ge 2 ] || { log "FAIL: initiator SAs gone during the outage ($nst)"; efail=1; }
			[ "$(grep -c 'MOBIKE initiator: local address' "$D/iked-i.log")" -eq 0 ] ||
				{ log "FAIL: an update was sent with no address"; efail=1; }
		fi
		case $scen in childrekey|ikerekey)
			# move DURING an exchange: hold the responder's answers so
			# the initiator's CREATE_CHILD_SA (exch 36) is in flight,
			# move while it is, then let the answers through
			( ip netns exec "$NSR" python3 "$HERE/tools/ikesniff.py" "$VR" "$HR" "$D/wire.tsv" ) >"$D/sniff.out" 2>&1 &
			SNIFF=$!
			# no harness probe while the SAs sit on an address that is
			# gone (rekeyed SAs land on it before the update moves
			# them): xfrm_audit.sh xa_hold, as in the peer MOBIKE rows
			xa_hold
			spi_pre=$(ip netns exec "$NSI" ip xfrm state 2>/dev/null | awk '/proto esp spi/{print $4}' | sort | tr '\n' ' ')
			ip netns exec "$NSR" iptables -A OUTPUT -p udp -m multiport --sports 500,4500 -j DROP
			i=0; until awk -F'\t' '$1=="in" && $2==36{f=1} END{exit !f}' "$D/wire.tsv" 2>/dev/null || [ "$i" -ge 300 ]; do
				i=$((i+1)); sleep 0.2; done
			awk -F'\t' '$1=="in" && $2==36{f=1} END{exit !f}' "$D/wire.tsv" 2>/dev/null ||
				{ log "FAIL: no CREATE_CHILD_SA from the initiator within 60 s"; efail=1; }
			;;
		esac
		# the move
		ip netns exec "$NSI" ip addr add "$HM/$PL" dev "$VI" $NODAD
		ip netns exec "$NSI" ip route replace "$HR/$HL" dev "$VI" src "$HM"
		# the kernel flushes a device's routes when its last IPv4
		# address goes (loss): the new network brings the inner route
		# back, as DHCP would; a no-op otherwise
		ip netns exec "$NSI" ip route replace "$TS_R/$HL" dev "$VI" src "$TS_I"
		[ "$scen" = loss ] || ip netns exec "$NSI" ip addr del "$HI/$PL" dev "$VI"
		case $scen in childrekey|ikerekey)
			ip netns exec "$NSR" iptables -D OUTPUT -p udp -m multiport --sports 500,4500 -j DROP ;;
		esac
		moved=0; i=0
		while [ "$i" -lt 100 ]; do
			ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -q "^src $HR dst $NEW" &&
			ip netns exec "$NSI" ip xfrm state 2>/dev/null | grep -q "^src $HM dst $HR" && { moved=1; break; }
			i=$((i+1)); sleep 0.2
		done
		case $scen in childrekey|ikerekey)
			# the rekey must complete too (its answer came back), and
			# the UPDATE after it: exch 36 out, then exch 37 in
			i=0; until awk -F'\t' '$1=="out" && $2==36{r=1} r && $1=="in" && $2==37{f=1} END{exit !f}' "$D/wire.tsv" || [ "$i" -ge 150 ]; do
				i=$((i+1)); sleep 0.2; done
			awk -F'\t' '$1=="out" && $2==36{r=1} r && $1=="in" && $2==37{f=1} END{exit !f}' "$D/wire.tsv" ||
				{ log "FAIL: no rekey answer followed by an INFORMATIONAL"; efail=1; }
			moved=0; i=0
			while [ "$i" -lt 100 ]; do
				ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -q "^src $HR dst $NEW" &&
				ip netns exec "$NSI" ip xfrm state 2>/dev/null | grep -q "^src $HM dst $HR" &&
				! ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -q "^src $HR dst $OLD\$" && { moved=1; break; }
				i=$((i+1)); sleep 0.2
			done
			spi_post=$(ip netns exec "$NSI" ip xfrm state 2>/dev/null | awk '/proto esp spi/{print $4}' | sort | tr '\n' ' ')
			log "mobike: $scen esp before=[$spi_pre] after=[$spi_post]"
			if [ "$scen" = ikerekey ]; then
				# the update rides the NEW IKE SA (other SPIs than
				# IKE_SA_INIT's), so the rekeyed SA is the one moved
				ike0=$(awk -F'\t' '$2==34{print $4; exit}' "$D/wire.tsv")
				[ -z "$ike0" ] && ike0=$(awk -F'\t' '$2==36{print $4; exit}' "$D/wire.tsv")
				nnew=$(awk -F'\t' -v o="$ike0" '$1=="in" && $2==37 && $4!=o' "$D/wire.tsv" | wc -l)
				log "mobike: INFORMATIONAL on a new IKE SPI=$nnew (old $ike0)"
				[ "$nnew" -ge 1 ] || { log "FAIL: the update did not ride the rekeyed IKE SA"; efail=1; }
			fi
			if [ "$scen" = childrekey ]; then
				[ "$spi_post" != "$spi_pre" ] || { log "FAIL: child SPIs unchanged: the rekey never completed"; efail=1; }
			fi
			kill "$SNIFF" 2>/dev/null
			xa_release ;;
		esac
		upd1=$(grep -c "UPDATE_SA_ADDRESSES" "$D/iked-r.log")
		upi=$(grep -c "MOBIKE initiator: local address" "$D/iked-i.log")
		log "mobike: initiator updates=$upi responder UPDATE lines $upd0 -> $upd1 moved=$moved"
		if [ "$scen" = return ] && [ "$moved" -eq 1 ]; then
			# RFC 4555: moving back to the original address is just
			# another update; both seats must return to $HI
			ip netns exec "$NSI" ip addr add "$HI/$PL" dev "$VI" $NODAD
			ip netns exec "$NSI" ip route replace "$HR/$HL" dev "$VI" src "$HI"
			ip netns exec "$NSI" ip addr del "$HM/$PL" dev "$VI"
			back=0; i=0
			while [ "$i" -lt 100 ]; do
				ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -q "^src $HR dst $HI\$" &&
				ip netns exec "$NSI" ip xfrm state 2>/dev/null | grep -q "^src $HI dst $HR\$" &&
				! ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -q "^src $HR dst $HM\$" && { back=1; break; }
				i=$((i+1)); sleep 0.2
			done
			upi2=$(grep -c "MOBIKE initiator: local address" "$D/iked-i.log")
			log "mobike: return to $HI back=$back initiator updates $upi -> $upi2"
			[ "$back" -eq 1 ] || { log "FAIL: SAs did not return to $HI"; efail=1; }
			[ "$upi2" -gt "$upi" ] || { log "FAIL: no update for the return"; efail=1; }
			# the remaining checks below run against the original address
			NEW=$HI; OLD=$HM
		fi
		if [ "$scen" = flap ] && [ "$moved" -eq 1 ]; then
			# 10 rapid flaps HM <-> HI (address and route events back to
			# back, no settling), ending on $HI: iked must converge on
			# the final address with a bounded number of updates (RFC
			# 4555 s3.5 leaves the pacing to the initiator; one update
			# in flight at a time, no storm).
			upf0=$(grep -c "MOBIKE initiator: local address" "$D/iked-i.log")
			k=0; cur=$HM
			while [ "$k" -lt 10 ]; do
				nxt=$HI; [ "$cur" = "$HI" ] && nxt=$HM
				ip netns exec "$NSI" ip addr add "$nxt/$PL" dev "$VI" $NODAD
				ip netns exec "$NSI" ip route replace "$HR/$HL" dev "$VI" src "$nxt"
				ip netns exec "$NSI" ip addr del "$cur/$PL" dev "$VI"
				cur=$nxt; k=$((k+1))
			done
			# 10 flaps from HM end on HM; one more to finish on HI
			ip netns exec "$NSI" ip addr add "$HI/$PL" dev "$VI" $NODAD
			ip netns exec "$NSI" ip route replace "$HR/$HL" dev "$VI" src "$HI"
			ip netns exec "$NSI" ip addr del "$HM/$PL" dev "$VI"
			back=0; i=0
			while [ "$i" -lt 150 ]; do
				ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -q "^src $HR dst $HI\$" &&
				ip netns exec "$NSI" ip xfrm state 2>/dev/null | grep -q "^src $HI dst $HR\$" &&
				! ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -q "^src $HR dst $HM\$" &&
				{ back=1; break; }
				i=$((i+1)); sleep 0.2
			done
			upf1=$(grep -c "MOBIKE initiator: local address" "$D/iked-i.log")
			nupd=$((upf1 - upf0))
			log "mobike: flap x11 converged=$back updates during the flaps=$nupd"
			[ "$back" -eq 1 ] || { log "FAIL: SAs did not converge on the final address $HI"; efail=1; }
			[ "$nupd" -ge 1 ] && [ "$nupd" -le 2 ] ||
				{ log "FAIL: $nupd updates for 11 address changes (want 1..2: the burst must be debounced)"; efail=1; }
			NEW=$HI; OLD=$HM
		fi
		if [ "$scen" = off ] || [ "$scen" = optout ] || [ "$scen" = pinned ]; then
			# control: give the default-off initiator the same window
			# pinned: on, but interface ike lists only the old
			# address; wait for iked's decision (event, not time)
			if [ "$scen" = pinned ]; then
				i=0; until grep -q "MOBIKE initiator: no IKE socket on $HM" "$D/iked-i.log" || [ "$i" -ge 50 ]; do
					i=$((i+1)); sleep 0.2; done
				grep -q "MOBIKE initiator: no IKE socket on $HM" "$D/iked-i.log" ||
					{ log "FAIL: iked never declined the move for its pinned address"; efail=1; }
				upi=$(grep -c "MOBIKE initiator: local address" "$D/iked-i.log")
				grep -q "failed to find a socket" "$D/iked-i.log" &&
					{ log "FAIL: iked transmitted without a socket"; efail=1; }
			fi
			[ "$upi" -eq 0 ] || { log "FAIL: mobike_initiate off but an update was sent"; efail=1; }
			[ "$moved" -eq 0 ] || { log "FAIL: SAs moved with mobike_initiate off"; efail=1; }
			ip netns exec "$NSR" ip xfrm state | grep -q "^src $HR dst $OLD" ||
				{ log "FAIL: responder SA left $OLD without an update"; efail=1; }
		else
			[ "$upi" -ge 1 ] || { log "FAIL: the initiator never sent UPDATE_SA_ADDRESSES"; efail=1; }
			[ "$upd1" -gt "$upd0" ] || { log "FAIL: the responder saw no UPDATE_SA_ADDRESSES"; efail=1; }
			[ "$moved" -eq 1 ] || { log "FAIL: SAs did not move to $NEW (responder) / $HM (initiator)"; efail=1; }
			ip netns exec "$NSR" ip xfrm state | grep -q "^src $HR dst $OLD" &&
				{ log "FAIL: a responder SA still targets $OLD"; efail=1; }
			nr=$(ip netns exec "$NSR" ip xfrm state | grep -c 'encap type espinudp')
			ni=$(ip netns exec "$NSI" ip xfrm state | grep -c 'encap type espinudp')
			log "mobike: espinudp SAs after the move: responder=$nr initiator=$ni"
			case $scen in
			natin|tcp) [ "$nr" -ge 2 ] && [ "$ni" -ge 2 ] ||
				{ log "FAIL: ESP not UDP-encapsulated on the new path"; efail=1; } ;;
			*) [ "$nr" -eq 0 ] && [ "$ni" -eq 0 ] ||
				{ log "FAIL: ESP still UDP-encapsulated on a NAT-free path"; efail=1; } ;;
			esac
			if [ "$scen" = tcp ]; then
				sleep 1; kill "$DUMP" 2>/dev/null; sleep 1
				syn=$(tcpdump -nn -r "$D/wire.pcap" "src host $NEW and tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0" 2>/dev/null | wc -l)
				log "mobike: TCP SYNs from $NEW=$syn"
				[ "$syn" -ge 1 ] || { log "FAIL: no TCP connection from the new address"; efail=1; }
				# RFC 9329 s6: the reply must go back over the stream the
				# update arrived on (from the new address), not the old one
				grep -q "routed over stream to $NEW\\[" "$D/iked-r.log" ||
					{ log "FAIL: the responder did not answer over the new TCP stream"; efail=1; }
			fi
			if [ -n "$NOMIG" ]; then
				for s in r i; do
					grep -q "moved [1-9][0-9]* SA(s) and [1-9][0-9]* policy template" "$D/iked-$s.log" ||
						{ log "FAIL: iked ($s) did not take the no-MIGRATE path"; efail=1; }
				done
			fi
			ip netns exec "$NSI" ping -c3 -i0.3 -W2 -I "$TS_I" "$TS_R" >/dev/null 2>&1 ||
				{ log "FAIL: ICMP after the move"; efail=1
				  for n in "$NSR" "$NSI"; do ip netns exec "$n" ip -s xfrm state; ip netns exec "$n" cat /proc/net/xfrm_stat; done >"$D/after-move.txt" 2>&1; }
		fi
	fi
	for s in r i; do pgrep -f -- "iked -F -f $C/$s.conf" >/dev/null 2>&1 || { log "FAIL: iked ($s) exited"; efail=1; }; done
	grep -h "ERROR: AddressSanitizer\|runtime error:" "$D"/iked-*.out 2>/dev/null | head -3 | while read -r l; do log "FAIL: $l"; done
	grep -qh "ERROR: AddressSanitizer\|runtime error:" "$D"/iked-*.out 2>/dev/null && efail=1
	kill "$DUMP" 2>/dev/null || true
	pkill -9 -f "$C/" 2>/dev/null || true
	sleep 1
	ip netns del "$NSR" 2>/dev/null || true
	ip netns del "$NSI" 2>/dev/null || true
	rm -rf "$PRIVRES_R" "$PRIVRES_I"
	return $efail
}
