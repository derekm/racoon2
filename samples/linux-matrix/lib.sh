# shared by linux-matrix kinds. sourced, not executed.
# shellcheck disable=SC2034
NS="${R2_NS:-r2c}"
VETH_H="${R2_VETH_H:-r2h}"
VETH_C="${R2_VETH_C:-r2n}"
HIP="${R2_HIP:-192.0.2.1}"
CIP="${R2_CIP:-192.0.2.2}"
RIP="${R2_RIP:-}"
PREFIX="${R2_PREFIX:-/usr/local/racoon2}"
ETC="${PREFIX}/etc/racoon2"
SBIN="${PREFIX}/sbin"
# systemd unit names: the tree installs iked.service/spmd.service; a live
# box with locally-renamed units can override via R2_IKED_UNIT/R2_SPMD_UNIT.
IKED_UNIT="${R2_IKED_UNIT:-iked}"
SPMD_UNIT="${R2_SPMD_UNIT:-spmd}"

log() { printf '%s\n' "$*"; }

# netem's own dropped-datagram counter, read from `tc -s qdisc show`.
# A replay marker alone can pass with zero measured loss; this counter
# makes "replayed" and "actually dropped" agree (counted-drop gate).
tc_dropped() {
	_ns=$1 _dev=$2
	ip netns exec "$_ns" tc -s qdisc show dev "$_dev" 2>/dev/null \
		| grep -oE 'dropped [0-9]+' | head -1 | awk '{print $2}'
}

# procps-ng guard: fedora:44 container images ship no pgrep/pkill unless
# procps-ng is installed, so an alive gate would silently read 0 and a
# case-end pkill would no-op, leaking daemons.  Fail loudly once, here.
require_procps() {
	if ! command -v pgrep >/dev/null 2>&1 || ! command -v pkill >/dev/null 2>&1; then
		log "FAIL: pgrep/pkill not installed (procps-ng) — daemon alive/cleanup gates cannot run"
		return 1
	fi
}

# hex of a whole-file PSK. xxd is not on every minimal image; od is coreutils.
psk_file_hex() {
	f=$1
	if command -v xxd >/dev/null 2>&1; then
		xxd -p -c 256 "$f" | tr -d '\n'
		return 0
	fi
	od -An -tx1 "$f" | tr -d ' \n'
}

die() {
	printf 'FAIL: %s\n' "$*" >&2
	R2_CASE_FAIL=1
	return 1
}

# Per-row resource names derived from the case NAME (run.sh passes it as
# kind_* $1).  Two rows of the SAME kind get distinct netns / veth / unix
# socket / log / resume-dir names, so they can run concurrently on one host
# (round-robin --shard fan-out, box sweeps) exactly like CI's separate
# containers.  Call at the top of every two-netns kind:
#     row_ns "$name"
# netns names have no 15-char cap (they are /var/run/netns symlinks); veth
# names DO (IFNAMSIZ), so VR/VI get a short 6-hex tag.  HR/HI addresses are
# deliberately NOT namespaced: they bind inside each row's own netns pair,
# so many rows of one kind may reuse the same subnet.  charon rows keep
# their host-global /var/run/charon.ctl and are pinned to one sweep shard.
row_ns() {
	_n=$1
	_tag=$(printf '%s' "$_n" | cksum | awk '{printf "%06x", $1}')
	NSR="n${_n}-r"; NSI="n${_n}-i"
	VR="v${_tag}1"; VI="v${_tag}2"
	SPMIF_R="/tmp/spmif-${_n}-r"; SPMIF_I="/tmp/spmif-${_n}-i"
	SOCK_R="/tmp/iked.sock-${_n}-r"; SOCK_I="/tmp/iked.sock-${_n}-i"
	PRIVRES_R="/tmp/r2-${_n}-resume-r"; PRIVRES_I="/tmp/r2-${_n}-resume-i"
	D="/tmp/r2-${_n}"; C="/tmp/r2-${_n}-conf"
}

require_root() {
	if [ "$(id -u)" -ne 0 ]; then
		die "need root (wsl.exe -d Ubuntu -u root)"
		return 1
	fi
}

# i2i_dataplane NSI DST [label]: once an i2i row's ESP child is up, prove it
# carries traffic BOTH ways: ping DST (the responder's tunnel address) from
# the initiator netns; the echo reply returns over the reverse SA.  The
# data-plane audit (xfrm_audit.sh) then asserts that both SAs' packet
# counters rose and that no integrity or xfrm_stat error appeared.  A row
# whose child is up but carries nothing fails here (R2_CASE_FAIL=1).
# i2i_wait_seat_sa NS [secs]: wait until NS holds a keyed inbound+outbound
# ESP pair (>= 2 ESP states).  The charon-initiator rows used to stop as
# soon as the RESPONDER's SAD appeared, so charon was killed before it
# installed its own side (Fedora container: always), and the child was
# never shown to carry anything.
i2i_wait_seat_sa() {
	_w=${2:-20}
	while [ "$_w" -gt 0 ]; do
		[ "$(ip -n "$1" xfrm state 2>/dev/null | grep -c '^	proto esp ')" -ge 2 ] && return 0
		sleep 1; _w=$((_w-1))
	done
	log "FAIL: data plane: $1 never installed its ESP SA pair (initiator side of the child)"
	return 1
}

# i2i_replay_loss_window HI HR SBIN SOCK_I D  -- the REPLAY kill-test loss
# window, shared by i2iinit-drop and i2iinit-drop576 (they were two copies
# of the same netem timing dance; that is how one-off flakes breed).
#
# Goal: force the responder to REPLAY its cached gen-0 IKE_INTERMEDIATE
# response.  We DROP EXACTLY ONE responder->initiator datagram (egress of
# the responder veth $VR, NF output hook) with nftables: the gen-0
# IKE_INTERMEDIATE response is the first responder IKE datagram >450 B
# (the base DH is ecp256, so the IKE_SA_INIT reply is small; the ML-KEM-768
# intermediate response KEr is ~1088 B, and at MTU 576 its first SKF
# fragment is also >450 B).  Losing it makes the initiator retransmit the
# gen-0 request, and the responder detects it by the cleartext outer msgid
# + replays (H1 replay marker logged in the responder log).  A quota
# "until 600 bytes" drops the one >450 B datagram and then stops matching,
# so every later datagram (IKE_AUTH, child) flows untouched -- the SA
# establishes normally and the test is DETERMINISTIC, never a
# wall-clock / probability flake.
#
# The loss is applied ONLY on the response direction, so the request side
# is clean.  Leaves the nft table armed for the rest of the row (netns
# teardown removes it); it is self-limiting to one drop.
#
# Requires the caller to have already: row_ns'd (so $NSR/$VR/$D are set),
# started the responder+initiator iked logs (resp log path = "$5"), and
# flushed stale xfrm.  On return, $I2I_NDROP carries the measured drop
# count (1 = the nft rule consumed its quota) and $I2I_SEEN is 1 if the
# intermediate round was observed.  Vars read: NSR VR D.
# Args: HI HR SBIN SOCK_I resp_log.
i2i_replay_loss_window() {
	_hi=$1 _hr=$2 _sbin=$3 _sock_i=$4 _resp=$5
	I2I_NDROP=0
	I2I_SEEN=0
	# The row retry loop re-invokes this helper in the same netns, so the
	# table may already exist from an earlier attempt.  `nft -f -` on an
	# existing table ADDS a second identical rule rather than replacing (so
	# the counter read below would hit the stale first rule's counter), and
	# the rule must be re-armed fresh for THIS attempt.  Delete first when
	# already present (i2ike-drop576.sh does the same between attempts), then
	# install fresh so every attempt drops exactly the one gen-0 response.
	if ip netns exec "$NSR" nft list table inet r2drop >/dev/null 2>&1; then
		ip netns exec "$NSR" nft delete table inet r2drop 2>/dev/null || true
	fi
	ip netns exec "$NSR" nft -f - 2>/dev/null <<'NFT' || \
		{ log "FAIL: cannot install the nft drop rule in $NSR (no nft?); abort"; return 1; }
table inet r2drop {
	chain out {
		type filter hook output priority 0; policy accept;
		udp sport { 500, 4500 } meta length > 450 quota until 600 bytes counter drop
	}
}
NFT

	"$_sbin/ikedctl" -s "$_sock_i" establish-sa isakmp inet "$_hi" "$_hr" sel_out >/dev/null 2>&1 || true

	# wait for the intermediate round (and the forced replay) to be observed,
	# bounded so a wedged SA cannot hang the row.  The nft rule is still
	# armed here; it drops at most one datagram, so the IKE_AUTH / child
	# exchange below is not starved.
	_w=$(( ${I2I_DROP_WINDOW_CAP:-40} ))
	while [ "$_w" -gt 0 ]; do
		if grep -qE "IKE_INTERMEDIATE ADDKE round complete|H1 replay" "$_resp" 2>/dev/null; then
			I2I_SEEN=1
			break
		fi
		sleep 1; _w=$((_w-1))
	done
	# read the rule's own drop counter: SUM every rule's counter so a retry
	# attempt (where each fresh install is the only rule present) counts
	# correctly rather than only seeing one rule.
	I2I_NDROP=$(ip netns exec "$NSR" nft list table inet r2drop 2>/dev/null \
		| grep -oE 'counter packets [0-9]+' | awk '{s+=$3} END{print s+0}')
	[ -n "${I2I_NDROP:-}" ] || I2I_NDROP=0
	log "drop-count window: nft dropped ${I2I_NDROP:-0} datagram (intermediate_seen=$I2I_SEEN)"
	return 0
}

i2i_dataplane() {
	if ! command -v ping >/dev/null 2>&1; then
		log "FAIL: data plane: ping(8) not installed, the row cannot prove its ESP child carries traffic"
		R2_CASE_FAIL=1
		return 1
	fi
	if ip netns exec "$1" ping -c 3 -i 0.2 -W 2 "$2" >/dev/null 2>&1; then
		log "data plane: ICMP echo ${3:+($3) }to $2 answered across the ESP child"
		# snapshot the counters now: a charon seat removes its SAs as
		# soon as the row tears it down, and the 0.5 s sampler can miss
		# the window between this echo and that teardown (Fedora: the
		# echo was answered, yet the initiator's last sample predated it)
		if [ -n "${XA_PID:-}" ] && [ -n "${XA_DIR:-}" ]; then
			xa_sample "$XA_ROW" SAMPLE "$XA_DIR"
		fi
		return 0
	fi
	log "FAIL: data plane: no ICMP echo reply from $2 across the ESP child${3:+ ($3)}"
	R2_CASE_FAIL=1
	return 1
}

detect_rip() {
	if [ -n "$RIP" ]; then
		return 0
	fi
	# The client must IKE to exactly the address iked is bound on.
	# Prefer the IP in the live racoon2.conf's ike interface ("IP port 500");
	# eth0 is NOT a safe default (mirrored WSL eth0 = Tailscale).
	RIP=$(sed -n 's/^[[:space:]]*\([0-9][0-9.]*\) port 500[[:space:]]*;.*$/\1/p' \
		"$ETC/racoon2.conf" 2>/dev/null | head -1)
	[ -n "$RIP" ] && return 0
	RIP=$(ip -4 -o addr show eth0 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1)
	[ -n "$RIP" ] || die "set R2_RIP"
}

charon_reset() {
	# the on-fabric ICMP cheat kill: ESP-decapped inner pings to the host
	# arrive with iif != r2h, so the DROP only kills non-tunnel ICMP.
	iptables -t raw -D PREROUTING -i "$VETH_H" -s "${CIP}/32" -p icmp -j DROP 2>/dev/null || true
	# The host's strongswan.service / charon-systemd owns the host vici
	# socket; rows used to stop it and kill every charon.  Rows now use a
	# private vici socket, swanctl dir and /run (I2I_SW_ROOT, review M6),
	# so the host daemon is left alone and only row charons are killed.
	i2i_charon_kill
	sleep 1
}

netns_up() {
	if ! ip netns list | grep -q "^${NS}[[:space:]]"; then
		ip link del "$VETH_H" 2>/dev/null || true
		ip netns add "$NS"
		ip link add "$VETH_H" type veth peer name "$VETH_C"
		ip link set "$VETH_C" netns "$NS"
		ip addr add "$HIP/24" dev "$VETH_H" 2>/dev/null || true
		ip link set "$VETH_H" up
		ip netns exec "$NS" ip addr add "$CIP/24" dev "$VETH_C"
		ip netns exec "$NS" ip link set "$VETH_C" up
		ip netns exec "$NS" ip link set lo up
		ip netns exec "$NS" ip route add default via "$HIP"
	fi
	echo 1 >/proc/sys/net/ipv4/ip_forward
	echo 0 >/proc/sys/net/ipv4/conf/all/rp_filter
	echo 0 >/proc/sys/net/ipv4/conf/${VETH_H}/rp_filter 2>/dev/null || true
}

iked_listening() {
	ss -ulnp | grep -q ":500 "
}

# R2_WORKERS empty: live systemd. Numeric: stop racoon2-iked, iked -F with
# RACOON2_CRYPTO_WORKERS, restore after the case. Does not touch spmd.
# Does not enable racoon2.target.
iked_apply_workers() {
	R2_IKED_EPHEMERAL_PID=
	R2_IKED_STOPPED=
	case ${R2_WORKERS-} in
	'')
		iked_listening || { log "FAIL: iked not on :500"; return 1; }
		return 0
		;;
	esac
	systemctl stop "$IKED_UNIT" 2>/dev/null || true
	R2_IKED_STOPPED=1
	i=0
	while iked_listening; do
		i=$((i + 1))
		if [ "$i" -gt 20 ]; then
			log "FAIL: :500 still bound after stop"
			return 1
		fi
		sleep 1
	done
	# Restart spmd first (drops IKE-bypass cache). Then flush whatever
	# boot SPD it reinstalled. Then spawn iked. Reverse order leaves a
	# 0/0→RIP tunnel SPD that captures IKE (XfrmInTmplMismatch).
	# Does not enable racoon2.target.
	systemctl restart "$SPMD_UNIT" || {
		log "FAIL: restart $SPMD_UNIT"
		return 1
	}
	i=0
	while [ ! -S /run/racoon2/spmif ] && [ ! -S /var/run/racoon2/spmif ]; do
		i=$((i + 1))
		if [ "$i" -gt 10 ]; then
			log "FAIL: no spmif after racoon2-spmd restart"
			return 1
		fi
		sleep 1
	done
	ip xfrm state flush || true
	ip xfrm policy flush || true
	: >/tmp/r2-iked-matrix.log
	(
		cd "$ETC" || exit 1
		export RACOON2_CRYPTO_WORKERS="$R2_WORKERS"
		exec "$SBIN/iked" -F -l /tmp/r2-iked-matrix.log
	) >>/tmp/r2-iked-matrix.log 2>&1 &
	R2_IKED_EPHEMERAL_PID=$!
	i=0
	while ! iked_listening; do
		i=$((i + 1))
		if [ "$i" -gt 20 ]; then
			log "FAIL: ephemeral iked workers=$R2_WORKERS not on :500"
			return 1
		fi
		if ! kill -0 "$R2_IKED_EPHEMERAL_PID" 2>/dev/null; then
			log "FAIL: ephemeral iked died workers=$R2_WORKERS"
			return 1
		fi
		sleep 1
	done
	log "iked pid=$R2_IKED_EPHEMERAL_PID workers=$R2_WORKERS"
	envn=$(tr '\0' '\n' <"/proc/${R2_IKED_EPHEMERAL_PID}/environ" 2>/dev/null | grep '^RACOON2_CRYPTO_WORKERS=' || true)
	if [ "$envn" != "RACOON2_CRYPTO_WORKERS=$R2_WORKERS" ]; then
		log "FAIL: environ $envn want RACOON2_CRYPTO_WORKERS=$R2_WORKERS"
		return 1
	fi
	if [ "$R2_WORKERS" -gt 0 ]; then
		grep -q "crypto workers: $R2_WORKERS" /tmp/r2-iked-matrix.log || {
			log "FAIL: no 'crypto workers: $R2_WORKERS' in log"
			return 1
		}
	fi
}

iked_restore() {
	if [ -n "${R2_IKED_EPHEMERAL_PID:-}" ]; then
		kill "$R2_IKED_EPHEMERAL_PID" 2>/dev/null || true
		wait "$R2_IKED_EPHEMERAL_PID" 2>/dev/null || true
		R2_IKED_EPHEMERAL_PID=
	fi
	if [ "${R2_IKED_STOPPED:-}" = 1 ]; then
		ip xfrm state flush || true
		ip xfrm policy flush || true
		systemctl start "$IKED_UNIT" 2>/dev/null || true
		R2_IKED_STOPPED=
		i=0
		while ! iked_listening; do
			i=$((i + 1))
			[ "$i" -gt 20 ] && break
			sleep 1
		done
	fi
}

# Linux FWD regression gate (spmd snapshot, e2bd9ef): the forwarded
# tunnel policy must carry the SAME tmpl as the matching dir-in policy.
# An inverted FWD (LAN→CP) breaks SSH-to-LAN while ping-to-box works.
# $1 = optional netns to read the SPD from (netns-wrapped SUT rows).
fwd_tmpl_check() {
	# read the SPD either from the caller's netns (netns-wrapped SUT) or the
	# host -- the awk body is identical either way.
	if [ -n "${1:-}" ]; then
		ip netns exec "$1" ip xfrm policy 2>/dev/null
	else
		ip xfrm policy 2>/dev/null
	fi | awk '
		function norm(s){gsub(/[ \t]+/," ",s); gsub(/^ | $/,"",s); return s}
		function flush(){
			if (sel != "" && tmpl != "" && isesp && mode == "tunnel") {
				key = norm(sel) "|" dir
				pol[key] = norm(tmpl)
			}
			sel=""; dir=""; tmpl=""; isesp=0; mode=""
		}
		/^src /{ if (sel != "") flush(); sel=$0; next }
		/^[ \t]*dst /{ sel=sel" "$0; next }
		/^[ \t]*dir /{ dir=$2; next }
		/^[ \t]*tmpl /{ tmpl=$0; next }
		/^[ \t]*proto esp /{ isesp=1; if ($0 ~ /mode tunnel/) mode="tunnel"; next }
		/^[ \t]*$/ { flush(); next }
		/^[ \t]*ptype /{ next }
		/^[ \t]*priority /{ next }
		{ next }
		END{
			flush()
			fail=0
			for (key in pol) {
				split(key, k, "|")
				if (k[2] != "in") continue
				fwd = pol[k[1] "|fwd"]
				if (fwd == "") continue
				if (fwd != pol[key]) {
					printf "FWD-TMPL-MISMATCH %s\n  in : %s\n  fwd: %s\n", k[1], pol[key], fwd
					fail=1
				}
			}
			exit fail
		}
	'
}
