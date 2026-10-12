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
	[ "$_any" = 1 ] || log "XA $1 INFO row created no n$1-* netns (not a live two-seat row)"
	return $_rc
}
