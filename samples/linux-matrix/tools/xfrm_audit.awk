# tools/xfrm_audit.awk -- analyse one netns' xfrm samples (see xfrm_audit.sh).
#
# Input: the sample log written by xa_sample: repeated sections
#   @@ BASE | @@ SAMPLE      -> `ip -s xfrm state` output follows
#   @@ STAT                  -> /proc/net/xfrm_stat follows
#   @@ ADDR                  -> `ip -o addr` follows
# BASE marks a sample taken before the row started (netns pre-existed);
# its xfrm_stat values are the baseline.  A netns first seen during the row
# has a baseline of 0 (counters of a new netns start at zero).
#
# Checks (each prints one "XA <ns> <check> PASS|FAIL|INFO ..." line):
#   icv     every auth-trunc / AEAD ICV length is exactly the RFC value
#           (RFC 2404 / 4868 / 3566 / 4494 / 7634); a 96-bit hmac(sha256)
#           is the KAME/ipsec-tools XFRMA_ALG_AUTH regression.
#   traffic a seat holding a keyed inbound+outbound SA pair must show the
#           packet counter of at least one outbound AND one inbound SA > 0.
#   safail  no SA's "stats: ... failed N" (per-SA integrity failures) > 0.
#   stat:X  each listed /proc/net/xfrm_stat error counter must not increase.
# vars: ns, allow_icv, allow_traffic, allow_safail (0/1); statallow
#       ("XfrmFoo=3,XfrmBar=1": counter may rise by at most that much).
function icv_want(alg) {
	if (alg == "hmac(md5)" || alg == "hmac(sha1)" || alg == "xcbc(aes)" ||
	    alg == "cmac(aes)" || alg == "hmac(rmd160)") return 96
	if (alg == "hmac(sha256)") return 128
	if (alg == "hmac(sha384)") return 192
	if (alg == "hmac(sha512)") return 256
	if (alg ~ /^rfc7539esp\(/) return 128
	return -1
}
function icv_ok_aead(alg, bits) {
	if (alg ~ /^rfc7539esp\(/) return bits == 128
	if (alg ~ /^rfc4106\(|^rfc4309\(|^rfc4543\(/) return bits == 64 || bits == 96 || bits == 128
	return 1
}
BEGIN {
	n = split("XfrmInError XfrmInBufferError XfrmInHdrError XfrmInStateProtoError XfrmInStateModeError XfrmInStateSeqError XfrmInStateMismatch XfrmInStateInvalid XfrmOutError XfrmOutBundleGenError XfrmOutBundleCheckError XfrmOutStateProtoError XfrmOutStateModeError XfrmOutStateSeqError XfrmOutStateInvalid XfrmFwdHdrError XfrmOutPolError XfrmInStateDirError XfrmOutStateDirError", CTR, " ")
	m = split(statallow, AL, ",")
	for (i = 1; i <= m; i++) { split(AL[i], kv, "="); allow[kv[1]] = kv[2] + 0 }
	sec = ""; fails = 0
}
/^@@ (BASE|SAMPLE)$/ { sec = $2; cur = ""; next }
/^@@ STAT$/ { sec = (sec == "BASE" ? "BSTAT" : "STAT"); next }
/^@@ ADDR$/ { sec = "ADDR"; next }
sec == "ADDR" {
	for (i = 1; i <= NF; i++)
		if ($i == "inet" || $i == "inet6") { a = $(i + 1); sub(/\/.*/, "", a); local[a] = 1 }
	next
}
sec == "STAT" || sec == "BSTAT" {
	if (NF == 2 && $1 ~ /^Xfrm/) {
		if (sec == "BSTAT") { if (!($1 in base)) base[$1] = $2 + 0 }
		else if ($2 + 0 > last[$1] + 0) last[$1] = $2 + 0
		seen_stat = 1
	}
	next
}
sec != "SAMPLE" && sec != "BASE" { next }
/^src / { s = $2; d = $4; cur = ""; pend = 1; next }
/^[ \t]+proto esp spi / {
	spi = $4; sub(/\(.*/, "", spi)
	cur = s ">" d ">" spi; src[cur] = s; dst[cur] = d; next
}
cur == "" { next }
/^[ \t]+auth-trunc / {
	alg = $2; bits = $NF + 0; keyed[cur] = 1
	w = icv_want(alg)
	if (w > 0 && bits != w && !(cur in badicv)) {
		badicv[cur] = alg " " bits " (want " w ")"; nbad++
	}
	next
}
/^[ \t]+aead / {
	alg = $2; bits = $NF + 0; keyed[cur] = 1
	if (!icv_ok_aead(alg, bits) && !(cur in badicv)) { badicv[cur] = alg " " bits; nbad++ }
	next
}
/^[ \t]+(enc|auth) / { keyed[cur] = 1; next }
/^[ \t]+lifetime current:/ { want_pk = 1; next }
want_pk && /\(packets\)/ {
	p = $2; sub(/\(.*/, "", p); p += 0
	if (p > maxpk[cur] + 0) maxpk[cur] = p
	want_pk = 0; next
}
/^[ \t]+replay-window [0-9]+ replay [0-9]+ failed [0-9]+/ {
	f = $NF + 0; if (f > safail[cur] + 0) safail[cur] = f; next
}
END {
	nk = 0
	for (k in keyed) nk++
	if (nk == 0) { printf "XA %s sa INFO no keyed ESP SA observed\n", ns; }
	# icv
	if (nbad > 0) {
		for (k in badicv) {
			printf "XA %s icv %s spi %s %s->%s: %s\n", ns, (allow_icv ? "XFAIL" : "FAIL"), substr(k, index(k, "0x")), src[k], dst[k], badicv[k]
			if (!allow_icv) fails++
		}
	} else if (nk > 0) {
		printf "XA %s icv PASS %d keyed SA(s), every ICV length exact\n", ns, nk
		if (allow_icv) { printf "XA %s icv XPASS (declared defect fixed: drop the xfrm_audit.tsv icv entry)\n", ns; fails++ }
	}
	# traffic
	oin = 0; oout = 0; hin = 0; hout = 0
	for (k in keyed) {
		if (src[k] in local) { hout = 1; if (maxpk[k] + 0 > 0) oout = 1 }
		if (dst[k] in local) { hin = 1; if (maxpk[k] + 0 > 0) oin = 1 }
	}
	if (hin && hout) {
		if (oin && oout) printf "XA %s traffic PASS outbound and inbound SA packet counters rose\n", ns
		else if (allow_traffic) printf "XA %s traffic XFAIL (declared) in=%d out=%d\n", ns, oin, oout
		else { printf "XA %s traffic FAIL keyed SA pair but packet counters flat (inbound rose=%d outbound rose=%d)\n", ns, oin, oout; fails++ }
		if (allow_traffic && oin && oout) { printf "XA %s traffic XPASS (declared no-traffic row moved data: drop the entry)\n", ns; fails++ }
	}
	# per-SA integrity failures
	sf = 0
	for (k in safail) if (safail[k] > 0) { sf = 1; printf "XA %s safail %s spi %s failed=%d\n", ns, (allow_safail ? "XFAIL" : "FAIL"), substr(k, index(k, "0x")), safail[k]; if (!allow_safail) fails++ }
	if (!sf && nk > 0) printf "XA %s safail PASS no per-SA integrity failures\n", ns
	# xfrm_stat
	if (seen_stat) {
		bad = ""
		for (i = 1; i <= n; i++) {
			c = CTR[i]; dlt = last[c] - base[c]
			if (dlt < 0) dlt = 0
			lim = (c in allow) ? allow[c] : 0
			if (dlt > lim) { bad = bad " " c "+" dlt; fails++ }
			else if (c in allow && dlt != lim) printf "XA %s stat:%s INFO rose %d (declared max %d)\n", ns, c, dlt, lim
		}
		if (bad != "") printf "XA %s xfrm_stat FAIL error counters rose:%s\n", ns, bad
		else printf "XA %s xfrm_stat PASS no xfrm_stat error counter rose\n", ns
	}
	exit (fails > 0)
}
