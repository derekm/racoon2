#!/bin/sh
# kinds/icvaudit.sh -- self-test of the data-plane audit (xfrm_audit.sh).
#
# Proves the audit that wraps every live row would catch the 96-bit
# hmac(sha256) ICV regression (rdratlos/racoon-ipsec-tools #145: the
# XFRMA_ALG_AUTH path truncates SHA-256 to 96 bits, RFC 4868 says 128).
# Two netns, static transport-mode ESP SAs installed with `ip xfrm`, so
# the row needs no IKE and isolates the audit itself:
#
#   icvaudit-ok          128/128: ping works; audit PASSes icv, traffic,
#                        safail and xfrm_stat.
#   icvaudit-96both      96/96 on both seats: the data plane works (both
#                        ends agree) -- exactly why the defect went unseen
#                        -- yet the audit must FAIL icv on both seats.
#   icvaudit-96mismatch  96 sender vs 128 receiver: ping fails; the audit
#                        must FAIL icv on the sender and see the receiver's
#                        per-SA integrity failures and XfrmInStateProtoError.
#
# The inner seats are named n<tag>-* with tag "icvx_<row>" so the outer
# run.sh audit (which watches n<row>-*) never sees them.

_icv_seats() {	# _icv_seats <tag> <icv-i> <icv-r>
	_t=$1 _ii=$2 _ir=$3
	_a="n$_t-i" _b="n$_t-r"
	_h=$(printf '%s' "$_t" | cksum | awk '{printf "%06x", $1}')
	ip netns del "$_a" 2>/dev/null; ip netns del "$_b" 2>/dev/null
	ip netns add "$_a" && ip netns add "$_b" || return 1
	ip link add "x${_h}a" netns "$_a" type veth peer name "x${_h}b" netns "$_b" || return 1
	ip -n "$_a" addr add 198.51.100.1/24 dev "x${_h}a"
	ip -n "$_b" addr add 198.51.100.2/24 dev "x${_h}b"
	for _n in "$_a" "$_b"; do ip -n "$_n" link set lo up; done
	ip -n "$_a" link set "x${_h}a" up; ip -n "$_b" link set "x${_h}b" up
	_ek=0x00112233445566778899aabbccddeeff
	_ak=0x00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
	# i->r SA: sender (i) uses _ii, receiver (r) uses _ir; r->i always _ir/_ii
	for _n in "$_a" "$_b"; do
		[ "$_n" = "$_a" ] && { _t1=$_ii; _t2=$_ii; } || { _t1=$_ir; _t2=$_ir; }
		ip -n "$_n" xfrm state add src 198.51.100.1 dst 198.51.100.2 proto esp spi 0x1001 \
			mode transport enc 'cbc(aes)' $_ek auth-trunc 'hmac(sha256)' $_ak "$_t1" || return 1
		ip -n "$_n" xfrm state add src 198.51.100.2 dst 198.51.100.1 proto esp spi 0x1002 \
			mode transport enc 'cbc(aes)' $_ek auth-trunc 'hmac(sha256)' $_ak "$_t2" || return 1
	done
	ip -n "$_a" xfrm policy add src 198.51.100.1 dst 198.51.100.2 proto icmp dir out tmpl proto esp mode transport
	ip -n "$_a" xfrm policy add src 198.51.100.2 dst 198.51.100.1 proto icmp dir in  tmpl proto esp mode transport
	ip -n "$_b" xfrm policy add src 198.51.100.2 dst 198.51.100.1 proto icmp dir out tmpl proto esp mode transport
	ip -n "$_b" xfrm policy add src 198.51.100.1 dst 198.51.100.2 proto icmp dir in  tmpl proto esp mode transport
}

kind_icvaudit() {
	name=$1
	require_root || return 1
	_t="icvx_$name"
	case $name in
	*-ok)         _ii=128 _ir=128 ;;
	*-96both)     _ii=96  _ir=96 ;;
	*-96mismatch) _ii=96  _ir=128 ;;
	*) log "FAIL $name: unknown icvaudit variant"; return 1 ;;
	esac
	_out=/tmp/r2-$name-xa.txt
	if ! _icv_seats "$_t" "$_ii" "$_ir"; then
		log "FAIL $name: could not build the static-SA seats"
		ip netns del "n$_t-i" 2>/dev/null; ip netns del "n$_t-r" 2>/dev/null
		return 1
	fi
	_save_pid=${XA_PID:-} _save_dir=${XA_DIR:-} _save_row=${XA_ROW:-}
	xa_start "$_t"
	ip netns exec "n$_t-i" ping -c 4 -i 0.3 -W 1 198.51.100.2 > "/tmp/r2-$name-ping.txt" 2>&1
	_pst=$?
	sleep 1
	xa_check "$_t" > "$_out" 2>&1
	_xst=$?
	XA_PID=$_save_pid XA_DIR=$_save_dir XA_ROW=$_save_row
	ip netns del "n$_t-i" 2>/dev/null; ip netns del "n$_t-r" 2>/dev/null
	cat "$_out"
	_bad=
	case $name in
	*-ok)
		[ "$_pst" = 0 ] || _bad="ping failed over matching 128-bit SAs"
		[ "$_xst" = 0 ] || _bad="${_bad:+$_bad; }audit failed on a clean 128/128 pair"
		[ "$(grep -c ' icv PASS ' "$_out")" = 2 ] || _bad="${_bad:+$_bad; }missing icv PASS on both seats"
		[ "$(grep -c ' traffic PASS ' "$_out")" = 2 ] || _bad="${_bad:+$_bad; }missing traffic PASS on both seats"
		[ "$(grep -c ' xfrm_stat PASS ' "$_out")" = 2 ] || _bad="${_bad:+$_bad; }missing xfrm_stat PASS on both seats"
		;;
	*-96both)
		[ "$_pst" = 0 ] || _bad="ping failed over matching 96-bit SAs (the defect must be data-plane silent)"
		[ "$_xst" != 0 ] || _bad="${_bad:+$_bad; }audit PASSED a 96-bit hmac(sha256) ICV"
		[ "$(grep -c ' icv FAIL .*hmac(sha256) 96 (want 128)' "$_out")" = 4 ] ||
			_bad="${_bad:+$_bad; }expected 4 icv FAIL lines (2 SAs x 2 seats)"
		;;
	*-96mismatch)
		[ "$_pst" != 0 ] || _bad="ping worked across a 96 vs 128 ICV mismatch"
		[ "$_xst" != 0 ] || _bad="${_bad:+$_bad; }audit PASSED a mismatched pair"
		grep -q "XA n$_t-i icv FAIL .*hmac(sha256) 96 (want 128)" "$_out" ||
			_bad="${_bad:+$_bad; }no icv FAIL on the 96-bit sender"
		grep -q "XA n$_t-r safail FAIL spi 0x00001001" "$_out" ||
			_bad="${_bad:+$_bad; }receiver per-SA integrity failures not reported"
		grep -q "XA n$_t-r xfrm_stat FAIL .*XfrmInStateProtoError" "$_out" ||
			_bad="${_bad:+$_bad; }receiver XfrmInStateProtoError not reported"
		;;
	esac
	if [ -n "$_bad" ]; then log "FAIL $name: $_bad"; return 1; fi
	log "PASS $name (audit verdict as required)"
	return 0
}
