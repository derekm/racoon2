#!/bin/sh
# xfrm_audit.sh -- data-plane audit run around EVERY live Linux matrix row.
#
# While a row runs, a background sampler snapshots, every 0.5 s, each netns
# the row owns (row_ns names them n<row>-*; nothing else is touched, so
# parallel run-shards.sh shards never see each other):
#     ip -s xfrm state, /proc/net/xfrm_stat, ip -o addr
# After the row, tools/xfrm_audit.awk asserts per seat:
#   icv      exact ICV length of every SA (auth-trunc hmac(sha256) ... 128,
#            sha384 192, sha512 256, sha1/md5/xcbc/cmac 96, chacha 128);
#            a 96-bit hmac(sha256) fails (ipsec-tools #145 / XFRMA_ALG_AUTH).
#   traffic  a seat with a keyed in+out SA pair saw both packet counters rise
#   safail   no per-SA integrity failure ("stats: ... failed N")
#   xfrm_stat no /proc/net/xfrm_stat error counter rose during the row
# This replaces the A2 claim in kinds/i2i_compliance.sh's header (A2 is an
# SPD-shape check; the counters are asserted here, for every row).
#
# A row may declare a KNOWN defect in xfrm_audit.tsv at its exact value
# (XFAIL); if the defect disappears the row fails with XPASS so the entry
# has to be removed.  R2_XFRM_AUDIT=0 disables the audit (box debugging
# only; CI never sets it).

XA_HERE=${HERE:-$(CDPATH= cd -- "$(dirname "$0")" && pwd)}

xa_sample() {	# xa_sample <row> <tag> <outdir>   (netns n<row>-*)
	for _xns in $(ip netns list 2>/dev/null | awk '{print $1}'); do
		case $_xns in "n$1-"*) ;; *) continue ;; esac
		{
			echo "@@ $2"
			ip -n "$_xns" -s xfrm state 2>/dev/null
			echo "@@ STAT"
			ip netns exec "$_xns" cat /proc/net/xfrm_stat 2>/dev/null
			echo "@@ ADDR"
			ip -n "$_xns" -o addr 2>/dev/null
		} >> "$3/$_xns.log" 2>/dev/null
	done
}

# xa_probe <row> <outdir>: the data-path probe.  Every row's established
# ESP children must carry traffic, not just exist in the SAD, so the harness
# itself (not each kind) sends a small probe across every keyed outbound
# child as soon as it appears: for each "dir out" policy with an ESP
# template whose selector is host-to-host (/32 or /128) and whose source is
# an address of this netns, once an outbound ESP SA towards the template's
# destination is keyed, 2 ICMP echos (selector proto any/icmp) or 2 UDP
# datagrams to the selector's dport (proto udp) are sent from the selector
# source.  An echo reply returns over the peer's reverse SA, so both seats'
# counters must rise; xfrm_audit.awk then asserts that ("traffic").  Each
# (netns, selector, outbound SPI) is probed once, so a rekeyed child is
# probed again.  Rows whose selectors are subnets or TCP-only are not
# probed here and must move data themselves (i2inatt, i2io4 ... do).
xa_probe() {
	# A row that declares a traffic exemption (xfrm_audit.tsv
	# `traffic 1`) must NOT be probed: it either never carries data
	# (i2ike-drain — drain deletes the child, so a probe landing beside
	# the delete makes one direction's counter racy) or moves data
	# itself.  Skipping the probe keeps counters flat so the declared
	# XFAIL path is the pass (and an XPASS would correctly flag data).
	[ -z "$(xa_allow "$1" traffic)" ] || return 0
	for _xns in $(ip netns list 2>/dev/null | awk '{print $1}'); do
		case $_xns in "n$1-"*) ;; *) continue ;; esac
		_xaddr=$(ip -n "$_xns" -o addr 2>/dev/null | awk '{ for (i = 1; i <= NF; i++) if ($i == "inet" || $i == "inet6") { a = $(i + 1); sub(/\/.*/, "", a); printf "%s ", a } }')
		_xst=$(ip -n "$_xns" xfrm state 2>/dev/null | awk '
			/^src / { d = $4; next }
			/^[ \t]+proto esp spi / { s = $4; sub(/\(.*/, "", s); print d, s }')
		[ -n "$_xst" ] || continue
		ip -n "$_xns" xfrm policy 2>/dev/null | awk '
			/^src / {
				ss = $2; dd = $4; pr = "any"; dp = ""
				for (i = 5; i <= NF; i++) {
					if ($i == "proto") pr = $(i + 1)
					if ($i == "dport") dp = $(i + 1)
				}
				out = 0; next
			}
			/^[ \t]+dir out / { out = 1; next }
			out && /^[ \t]+tmpl src / { td = $5; next }
			out && td != "" && /^[ \t]+proto esp / {
				if ((ss ~ /\/32$/ || ss ~ /\/128$/) && (dd ~ /\/32$/ || dd ~ /\/128$/)) {
					a = ss; b = dd; sub(/\/.*/, "", a); sub(/\/.*/, "", b)
					print a, b, pr, (dp == "" ? "-" : dp), td
				}
				td = ""; out = 0
			}' | while read -r _ps _pd _pp _pdp _ptd; do
			case " $_xaddr " in *" $_ps "*) ;; *) continue ;; esac
			_pspi=$(printf '%s\n' "$_xst" | awk -v t="$_ptd" '$1 == t { print $2; exit }')
			[ -n "$_pspi" ] || continue
			_pk="$_xns $_ps $_pd $_pp $_pdp $_pspi"
			grep -qxF "$_pk" "$2/probed" 2>/dev/null && continue
			printf '%s\n' "$_pk" >> "$2/probed"
			case $_pp in
			any|icmp|ipv6-icmp|icmpv6)
				ip netns exec "$_xns" ping -c 2 -i 0.2 -W 1 -I "$_ps" "$_pd" \
					>> "$2/probe.out" 2>&1 & ;;
			udp)
				[ "$_pdp" != - ] || continue
				ip netns exec "$_xns" bash -c 'for i in 1 2; do printf r2probe > "/dev/udp/$1/$2"; sleep 0.2; done' \
					bash "$_pd" "$_pdp" >> "$2/probe.out" 2>&1 & ;;
			esac
		done
	done
}

xa_enabled() {
	[ "${R2_XFRM_AUDIT:-1}" != 0 ] || return 1
	[ "$(id -u)" -eq 0 ] || return 1
	[ -r /proc/net/xfrm_stat ] || return 1
	return 0
}

xa_start() {	# xa_start <row>
	XA_ROW=$1; XA_PID=
	xa_enabled || return 0
	XA_DIR=/tmp/r2-xa-$1
	rm -rf "$XA_DIR"; mkdir -p "$XA_DIR"
	xa_sample "$1" BASE "$XA_DIR"
	(
		while :; do
			xa_sample "$XA_ROW" SAMPLE "$XA_DIR"
			[ "${R2_XFRM_PROBE:-1}" = 0 ] || xa_probe "$XA_ROW" "$XA_DIR"
			sleep 0.5
		done
	) >/dev/null 2>&1 &
	XA_PID=$!
}

# allowance lookup: xfrm_audit.tsv rows "regex<TAB>check<TAB>value<TAB>why"
xa_allow() {	# xa_allow <row> <check>  -> prints value or nothing
	[ -f "$XA_HERE/xfrm_audit.tsv" ] || return 0
	while IFS="$(printf '\t')" read -r _re _ck _val _why; do
		case $_re in ''|\#*) continue ;; esac
		[ "$_ck" = "$2" ] || continue
		printf '%s\n' "$1" | grep -Eqx "$_re" && { printf '%s\n' "$_val"; return 0; }
	done < "$XA_HERE/xfrm_audit.tsv"
}

xa_check() {	# xa_check <row>  -> 0 ok, 1 audit failure
	xa_enabled || return 0
	[ -n "${XA_PID:-}" ] && { kill "$XA_PID" 2>/dev/null; wait "$XA_PID" 2>/dev/null; }
	XA_PID=
	xa_sample "$1" SAMPLE "$XA_DIR"
	_ai=0; _at=0; _as=0
	[ -n "$(xa_allow "$1" icv)" ] && _ai=1
	[ -n "$(xa_allow "$1" traffic)" ] && _at=1
	[ -n "$(xa_allow "$1" safail)" ] && _as=1
	_sa=$(xa_allow "$1" stat)
	_rc=0 _any=0
	for _f in "$XA_DIR"/*.log; do
		[ -f "$_f" ] || continue
		_any=1
		_ns=$(basename "$_f" .log)
		awk -v ns="$_ns" -v allow_icv=$_ai -v allow_traffic=$_at \
			-v allow_safail=$_as -v statallow="$_sa" \
			-f "$XA_HERE/tools/xfrm_audit.awk" "$_f" || _rc=1
	done
	if [ "$_rc" != 0 ] && ! command -v ping >/dev/null 2>&1; then
		log "XA $1 FAIL ping(8) is not installed: the harness data-path probe could not run"
	fi
	[ "$_any" = 1 ] || log "XA $1 INFO row created no n$1-* netns (not a live two-seat row)"
	return $_rc
}
