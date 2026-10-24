#!/bin/sh
# kinds/i2ixfrm.sh -- XFRM-native SA features end to end: a marked flow
# (policy `mark {}`) and crypto offload (sa `offload {}`), iked<->iked on
# 192.0.7.x, each seat in its OWN netns with its own spmd/iked (no host
# daemon, unit or config file is touched).  Classical IKE (no ADDKE), so the
# rows run on every Linux lane, including the old-kernel guests where XFRMA_MARK
# on ALLOCSPI/NEWSA and XFRMA_OFFLOAD_DEV acceptance is the open question.
#
#   i2ixfrm-mark     both seats' policies carry mark 0x42/0xff.  Gate: every
#                    ESP state and every policy in both SADs/SPDs shows
#                    "mark 0x42/0xff"; marked echos (ping -m 66 = 0x42) move the
#                    outbound SA's packet counter on both seats; unmarked
#                    echos do NOT (they are outside the marked flow).
#   i2ixfrm-offload  responder's sa block names a netdevsim port as offload
#                    device.  Gate: both responder ESP states show "crypto
#                    offload parameters: dev <port>" with their own
#                    direction, and the netdevsim ipsec debugfs counts them.
#                    netdevsim is the kernel's own offload test device; it
#                    keys nothing on the wire, so ESP traffic over the veth
#                    still runs in software and the harness audit asserts it.
#                    Needs CONFIG_NETDEVSIM + ESP offload support: run.sh
#                    skips the row only on PROOF that a hand-installed
#                    offload SA is refused (nsim_offload_probe below).

# nsim_offload_probe: create a netdevsim port in a scratch netns, install one
# offload SA by hand and read it back.  Prints the proof either way; returns 0
# iff the kernel accepts and reports an offloaded SA.
nsim_offload_probe() {
	_pns=nsimprobe-$$
	_ok=1
	_perr=$(mktemp "${TMPDIR:-/tmp}/nsim-probe.XXXXXX") || { echo "mktemp failed"; return 1; }
	if ! modprobe netdevsim 2>"$_perr" && [ ! -d /sys/bus/netdevsim ]; then
		echo "modprobe netdevsim: $(tr '\n' ' ' <"$_perr") (kernel $(uname -r))"
		rm -f "$_perr"
		return 1
	fi
	if ! _pid=$(nsim_free_id 700); then
		echo "no free netdevsim id"; rm -f "$_perr"; return 1
	fi
	modprobe esp4_offload 2>/dev/null || true
	ip netns add "$_pns" || { echo "cannot create netns"; return 1; }
	if ! echo "$_pid 1" >/sys/bus/netdevsim/new_device 2>"$_perr"; then
		echo "netdevsim new_device: $(tr '\n' ' ' <"$_perr")"
		ip netns del "$_pns"
		rm -f "$_perr"
		return 1
	fi
	rm -f "$_perr"
	sleep 1
	_dev=$(ls /sys/bus/netdevsim/devices/netdevsim$_pid/net 2>/dev/null | head -1)
	if [ -z "$_dev" ]; then
		echo "netdevsim$_pid has no net port"
		_ok=1
	elif ! ip link set "$_dev" netns "$_pns" || ! ip -n "$_pns" link set "$_dev" up ||
	    ! ip -n "$_pns" addr add 198.18.7.1/24 dev "$_dev"; then
		echo "cannot move $_dev into the probe netns"
	elif ! _e=$(ip -n "$_pns" xfrm state add src 198.18.7.1 dst 198.18.7.2 \
	    proto esp spi 0x7001 reqid 1 mode tunnel \
	    aead 'rfc4106(gcm(aes))' 0x0102030405060708090a0b0c0d0e0f1011121314 128 \
	    offload dev "$_dev" dir out 2>&1); then
		echo "kernel $(uname -r) refused an offload SA on $_dev: $_e"
	elif ip -n "$_pns" xfrm state | grep -q "crypto offload parameters: dev $_dev"; then
		echo "kernel $(uname -r) accepts crypto offload on netdevsim port $_dev"
		_ok=0
	else
		echo "kernel $(uname -r) installed the SA but dropped its offload binding (no ESP offload support)"
	fi
	ip netns del "$_pns" 2>/dev/null
	echo "$_pid" >/sys/bus/netdevsim/del_device 2>/dev/null
	return $_ok
}

# nsim_free_id BASE: first netdevsim id >= BASE (BASE..BASE+199) with no
# device; netdevsim ids are host-global, so parallel shards must not reuse one
nsim_free_id() {
	_i=$1
	while [ "$_i" -lt $(($1 + 200)) ]; do
		[ -e "/sys/bus/netdevsim/devices/netdevsim$_i" ] || { echo "$_i"; return 0; }
		_i=$((_i + 1))
	done
	return 1
}

# x_teardown: idempotent cleanup of everything a row created, run on every
# exit path (including early FAIL returns): daemons, netns, veth, nsim device
x_teardown() {
	pkill -9 -f "$C/" 2>/dev/null || true
	sleep 1
	ip netns del "$NSR" 2>/dev/null || true
	ip netns del "$NSI" 2>/dev/null || true
	ip link del "$VR" 2>/dev/null || true
	if [ -n "${NSIM_ID:-}" ]; then
		echo "$NSIM_ID" >/sys/bus/netdevsim/del_device 2>/dev/null || true
		NSIM_ID=
	fi
	rm -rf "$PRIVRES_R" "$PRIVRES_I"
}

# x_mark_esp NS: mark arriving ESP so the marked inbound SA matches it
# (an SA lookup uses skb->mark; packets off the wire carry 0).
x_mark_esp() {
	if command -v nft >/dev/null 2>&1; then
		ip netns exec "$1" nft -f - <<NEOF || return 1
table inet r2mark {
	chain pre { type filter hook prerouting priority mangle; meta l4proto esp meta mark set 0x42; }
}
NEOF
	elif command -v iptables >/dev/null 2>&1; then
		ip netns exec "$1" iptables -t mangle -A PREROUTING -p esp -j MARK --set-mark 0x42 || return 1
	else
		log "FAIL: neither nft nor iptables: cannot mark inbound ESP"
		return 1
	fi
	# echo replies inherit the request's mark (else they leave unmarked,
	# outside the marked flow)
	ip netns exec "$1" sysctl -qw net.ipv4.fwmark_reflect=1
}

# x_out_pkts NS SRC DST: packet counter of the ESP SA SRC->DST
x_out_pkts() {
	ip -n "$1" -s xfrm state 2>/dev/null | awk -v s="$2" -v d="$3" '
		/^src / { cur = ($2 == s && $4 == d) }
		cur && /^[ \t]+[0-9]+\(bytes\), [0-9]+\(packets\)/ {
			sub(/.*\(bytes\), /, ""); sub(/\(packets\).*/, ""); print; exit }'
}

x_conf() {	# x_conf <file> <me> <peer> <passive> <myid> <peerid> <polextra> <saextra>
	cat > "$1" <<EOF
interface {
	ike { "$2"; };
	spmd { unix "$X_SPMIF"; };
	spmd_password "$ETC/spmd.pwd";
};
resolver { resolver off; };
remote matrix_x {
	acceptable_kmp { ikev2; };
	ikev2 {
		passive $4;
		my_id fqdn "$5";
		peers_id fqdn "$6";
		peers_ipaddr "$3";
		kmp_enc_alg { aes_gcm; };
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
	src "$2"; dst "$3";
	policy_index pol;
};
selector sel_in {
	direction inbound;
	dst "$2"; src "$3";
	policy_index pol;
};
policy pol {
	action auto_ipsec;
	remote_index matrix_x;
	ipsec_mode tunnel;
	ipsec_index { ipsec_e; };
	ipsec_level require;
	peers_sa_ipaddr "$3";
	my_sa_ipaddr "$2";
	$7
};
ipsec ipsec_e {
	ipsec_sa_lifetime_time 300 sec;
	sa_index esp_e;
};
sa esp_e {
	sa_protocol esp;
	esp_enc_alg { $X_ESP_ENC; };
	esp_auth_alg { non_auth; };
	$8
};
EOF
}

kind_i2ixfrm() {
	name=$1
	require_root || return 1
	[ -x "$SBIN/iked" ] || { log "FAIL: no $SBIN/iked"; return 1; }
	[ -f "$ETC/spmd.pwd" ] || { log "FAIL: no $ETC/spmd.pwd"; return 1; }
	[ -f "$ETC/psk/macos.psk" ] || { log "FAIL: no $ETC/psk/macos.psk"; return 1; }
	command -v ping >/dev/null 2>&1 || { log "FAIL: ping(8) not installed"; return 1; }

	row_ns "$name"
	HR=192.0.7.1; HI=192.0.7.2
	rm -rf "$PRIVRES_R" "$PRIVRES_I" "$D" "$C"; mkdir -p "$PRIVRES_R" "$PRIVRES_I" "$D" "$C"
	pkill -9 -f "$C/" 2>/dev/null || true
	rm -f "$SPMIF_R" "$SPMIF_I" "$SOCK_R" "$SOCK_I"
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

	POLX=; SAX=; NSIM_ID=; NSIM_DEV=
	case "$name" in
	*-mark)
		POLX='mark { value 0x42; mask 0xff; };'
		x_mark_esp "$NSR" && x_mark_esp "$NSI" || { log "FAIL: cannot mark inbound ESP"; x_teardown; return 1; }
		;;
	*-offload)
		modprobe netdevsim 2>/dev/null || true
		modprobe esp4_offload 2>/dev/null || true
		_id=$(nsim_free_id 900) || { log "FAIL: no free netdevsim id"; x_teardown; return 1; }
		echo "$_id 1" >/sys/bus/netdevsim/new_device || { log "FAIL: netdevsim new_device"; x_teardown; return 1; }
		NSIM_ID=$_id	# owned by this row from here on: x_teardown deletes it
		sleep 1
		NSIM_DEV=$(ls /sys/bus/netdevsim/devices/netdevsim$NSIM_ID/net | head -1)
		ip link set "$NSIM_DEV" netns "$NSR" && ip -n "$NSR" link set "$NSIM_DEV" up ||
			{ log "FAIL: cannot move netdevsim port into $NSR"; x_teardown; return 1; }
		log "offload device: netdevsim$NSIM_ID port $NSIM_DEV in $NSR"
		SAX="offload { dev \"$NSIM_DEV\"; };"
		;;
	*) log "FAIL: unknown i2ixfrm arm $name"; x_teardown; return 1 ;;
	esac

	# netdevsim offloads only rfc4106 with a 128-bit key (+32-bit salt):
	# pin the key length on both seats rather than rely on the default
	# aes_gcm key length, which the offload gate then proves (160-bit
	# keymat in the SAD, the exact shape nsim_offload_probe installed)
	X_ESP_ENC="aes_gcm, 128"
	X_SPMIF=$SPMIF_R x_conf "$C/responder.conf" "$HR" "$HI" on racoon2-matrix r2init-matrix "$POLX" "$SAX"
	X_SPMIF=$SPMIF_I x_conf "$C/initiator.conf" "$HI" "$HR" off r2init-matrix racoon2-matrix "$POLX" ""

	for ns in "$NSR:$HR:$HI" "$NSI:$HI:$HR"; do
		NSX=${ns%%:*}; rest=${ns#*:}; LX=${rest%%:*}; PX=${rest#*:}
		for p in 500 4500; do
			ip netns exec "$NSX" ip xfrm policy add src "$PX"/32 dst "$LX"/32 proto udp sport "$p" dport "$p" dir in  ptype main action allow 2>/dev/null || true
			ip netns exec "$NSX" ip xfrm policy add src "$LX"/32 dst "$PX"/32 proto udp sport "$p" dport "$p" dir out ptype main action allow 2>/dev/null || true
		done
	done

	( ip netns exec "$NSR" "$SBIN/spmd" -F -f "$C/responder.conf" ) >"$D/resp-spmd.log" 2>&1 &
	i=0; until [ -S "$SPMIF_R" ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
	( ip netns exec "$NSR" env RACOON2_ADMIN_SOCK="$SOCK_R" RACOON2_RESUME_DIR="$PRIVRES_R" \
	    "$SBIN/iked" -F -f "$C/responder.conf" -D 0x0001 -l "$D/resp-iked.log" ) >"$D/resp-iked.out" 2>&1 &
	( ip netns exec "$NSI" "$SBIN/spmd" -F -f "$C/initiator.conf" ) >"$D/init-spmd.log" 2>&1 &
	i=0; until [ -S "$SPMIF_I" ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
	( ip netns exec "$NSI" env RACOON2_ADMIN_SOCK="$SOCK_I" RACOON2_RESUME_DIR="$PRIVRES_I" \
	    "$SBIN/iked" -F -f "$C/initiator.conf" -D 0x0001 -l "$D/init-iked.log" ) >"$D/init-iked.out" 2>&1 &
	sleep 2
	"$SBIN/ikedctl" -s "$SOCK_I" establish-sa isakmp inet "$HI" "$HR" sel_out >/dev/null 2>&1 || true

	up=0; i=0
	while [ "$i" -lt 45 ]; do
		re=$(ip -n "$NSR" xfrm state 2>/dev/null | grep -c 'proto esp')
		ie=$(ip -n "$NSI" xfrm state 2>/dev/null | grep -c 'proto esp')
		if [ "${re:-0}" -ge 2 ] && [ "${ie:-0}" -ge 2 ]; then
			log "ESP child UP: responder esp=$re initiator esp=$ie after ${i}s"
			up=1; break
		fi
		i=$((i+1)); sleep 1
	done
	ok=$up
	for S in "$NSR" "$NSI"; do
		ip -n "$S" xfrm state >"$D/$S-sad.txt" 2>&1
		ip -n "$S" xfrm policy >"$D/$S-spd.txt" 2>&1
	done

	case "$name" in
	*-mark)
		for S in "$NSR" "$NSI"; do
			# every ESP state block must carry the mark line
			nesp=$(grep -c 'proto esp' "$D/$S-sad.txt")
			nmk=$(awk '/^src /{e=0} /proto esp/{e=1} e && /mark 0x42\/0xff/{n++; e=0} END{print n+0}' "$D/$S-sad.txt")
			# every policy that templates ESP must carry it too
			np=$(awk '/^src /{if(t&&!m)bad++; t=0; m=0} /proto esp/{t=1} /mark 0x42\/0xff/{m=1} END{if(t&&!m)bad++; print bad+0}' "$D/$S-spd.txt")
			log "$S: esp states=$nesp marked=$nmk; ESP policies without the mark=$np"
			if [ "$nesp" -lt 2 ] || [ "$nmk" -ne "$nesp" ] || [ "$np" -ne 0 ]; then
				r2_gate "mark.sadspd.$S" FAIL "esp=$nesp marked=$nmk unmarked_policies=$np"
				ok=0
			else
				r2_gate "mark.sadspd.$S" PASS "esp=$nesp marked=$nmk"
			fi
		done
		if [ "$up" -eq 1 ]; then
			oi0=$(x_out_pkts "$NSI" "$HI" "$HR"); or0=$(x_out_pkts "$NSR" "$HR" "$HI")
			ip netns exec "$NSI" ping -c 3 -i 0.2 -W 2 "$HR" >/dev/null 2>&1
			oi1=$(x_out_pkts "$NSI" "$HI" "$HR"); or1=$(x_out_pkts "$NSR" "$HR" "$HI")
			if ip netns exec "$NSI" ping -m 66 -c 3 -i 0.2 -W 2 "$HR" >/dev/null 2>&1; then
				r2_gate mark.echo PASS "marked ICMP echo answered"
			else
				r2_gate mark.echo FAIL "marked ICMP echo not answered across the marked child"
				ok=0
			fi
			oi2=$(x_out_pkts "$NSI" "$HI" "$HR"); or2=$(x_out_pkts "$NSR" "$HR" "$HI")
			log "outbound ESP packets init ${oi0:-?}->${oi1:-?}->${oi2:-?} resp ${or0:-?}->${or1:-?}->${or2:-?} (unmarked, then marked)"
			if [ "${oi1:-x}" != "${oi0:-y}" ] || [ "${or1:-x}" != "${or0:-y}" ]; then
				r2_gate mark.unmarked_bypass FAIL "unmarked echos used the marked SA"
				ok=0
			else
				r2_gate mark.unmarked_bypass PASS "SA counters flat for unmarked echos"
			fi
			if [ "$((${oi2:-0} - ${oi1:-0}))" -lt 3 ] || [ "$((${or2:-0} - ${or1:-0}))" -lt 3 ]; then
				r2_gate mark.marked_via_sa FAIL "marked echos did not traverse both seats' marked SAs"
				ok=0
			else
				r2_gate mark.marked_via_sa PASS "init +$((oi2 - oi1)) resp +$((or2 - or1)) packets"
			fi
		fi
		;;
	*-offload)
		if grep -q 'aead rfc4106(gcm(aes)) 0x[0-9a-f]\{40\} ' "$D/$NSR-sad.txt"; then
			r2_gate offload.alg PASS "responder ESP is rfc4106 AES-128-GCM (the netdevsim-offloadable shape)"
		else
			r2_gate offload.alg FAIL "responder ESP is not rfc4106 AES-128-GCM: $(grep -m1 aead "$D/$NSR-sad.txt")"
			ok=0
		fi
		for dir in in out; do
			if grep -A12 'proto esp' "$D/$NSR-sad.txt" | grep -q "crypto offload parameters: dev $NSIM_DEV dir $dir"; then
				r2_gate "offload.bound.$dir" PASS "responder ESP state offloaded to $NSIM_DEV dir $dir"
			else
				r2_gate "offload.bound.$dir" FAIL "responder SAD lacks an ESP state offloaded to $NSIM_DEV dir $dir"
				ok=0
			fi
		done
		if grep -q 'crypto offload' "$D/$NSI-sad.txt"; then
			r2_gate offload.initiator_none FAIL "initiator (no offload config) has an offloaded SA"
			ok=0
		else
			r2_gate offload.initiator_none PASS "initiator SAs not offloaded"
		fi
		dbg=$(find /sys/kernel/debug/netdevsim -path "*netdevsim$NSIM_ID*" -name ipsec 2>/dev/null | head -1)
		if [ -n "$dbg" ]; then
			cnt=$(sed -n 's/.*SA count=\([0-9]*\).*/\1/p' "$dbg" | head -1)
			log "netdevsim ipsec debugfs: SA count=${cnt:-?}"
			if [ "${cnt:-0}" -ge 2 ]; then
				r2_gate offload.nsim_count PASS "netdevsim holds $cnt SAs"
			else
				r2_gate offload.nsim_count FAIL "netdevsim holds ${cnt:-0} SAs, want >= 2"; ok=0
			fi
		else
			log "netdevsim ipsec debugfs not mounted; SAD binding is the proof"
		fi
		[ "$up" -eq 1 ] && i2i_dataplane "$NSI" "$HR" "$name"
		;;
	esac

	x_teardown
	if [ "$ok" -ne 1 ]; then
		log "FAIL: $name (up=$up)"
		for f in resp-iked init-iked; do
			log "--- $f.log ---"
			grep -E 'mark|offload|IKE_AUTH|abort|err=|failed' "$D/$f.log" 2>/dev/null | tail -8
		done
		return 1
	fi
	return 0
}
