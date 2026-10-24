#!/bin/sh
# tools/compat-matrix.sh -- derive the peer x feature x gate compatibility
# table (NEWS) from cases.tsv, so the published matrix cannot drift from the
# rows that actually run.  Usage: sh tools/compat-matrix.sh [cases.tsv]
#   peer:    strongSwan (charon) when the row puts charon on a seat (kinds
#            ikev1, ikev2, i2ieap, i2iconf_addrpool, or a *-charon* /
#            -strongswan row), else iked<->iked
#   gate:    where the row counts: ci = the Ubuntu and Fedora full matrix
#            (the kernel lane runs a quick subset), addke = Fedora/OpenSSL
#            3.5 lane only, box = box only,
#            nsim/pfkey/dpd = capability lanes (run.sh)
#   each cell: "<n> <gate>[, <n> <gate>...]"
F=${1:-$(dirname "$0")/../cases.tsv}
awk -F'\t' '
function feat(k, n) {
	if (k ~ /^(unit|admin)$/) return "unit / admin socket"
	if (k == "icvaudit" || k == "pfkeyicv") return "ESP ICV lengths"
	if (k == "ikev1") return "IKEv1"
	if (k == "i2ieap") return "EAP (RADIUS)"
	if (k == "i2ipubkey") return "X.509 / raw public key auth"
	if (k == "i2iresume") return "session resumption (RFC 5723)"
	if (k == "i2inatt" || k == "i2io4") return "NAT-T / UDP encapsulation"
	if (k == "i2iv6") return "IPv6"
	if (k == "i2ixfrm") return "XFRM mark / offload"
	if (k == "i2i_nsawarn" || k == "i2i_neg") return "deprecated-suite policy"
	if (k ~ /^i2iconf_/) return "config: pools, lifetimes"
	if (k ~ /^i2ike_(redirect2)$/) return "redirect (RFC 5685)"
	if (k ~ /drop|dup|replay|silence|collide|drain/) return "loss, replay, collisions"
	if (n ~ /ppk/) return "PPK (RFC 8784)"
	if (n ~ /childless/) return "childless (RFC 6023)"
	if (k ~ /^(i2iinit|i2ike|i2ikesa|i2idh|i2ilw|ikev2)/ && n ~ /cbc|ctr|ccm|gcm|prf|sha|xcbc|cmac|3des|esn|dh|modp|ecp|curve/) return "proposal shapes (ciphers, PRFs, DH)"
	if (k ~ /^(i2iinit|i2ike|i2ikesa|i2ilw|ikev2)/) return "PQC ADDKE (RFC 9242/9370)"
	return "other"
}
/^#/ || NF < 3 || $1 == "" { next }
{
	n = $1; k = $2; g = $6; if (g == "" || g == "-") g = "ci"
	p = (k ~ /^(ikev1|ikev2|i2ieap|i2iconf_addrpool)$/ || n ~ /charon|strongswan/) ? "strongSwan" : "iked"
	f = feat(k, n); key = f SUBSEP p SUBSEP g
	c[key]++; F[f] = 1; G[g] = 1
}
END {
	print "| feature | iked <-> iked | iked <-> strongSwan |"
	print "|---|---|---|"
	ng = split("ci addke nsim pfkey dpd box", go, " ")
	nf = 0; for (f in F) fl[++nf] = f
	for (i = 1; i <= nf; i++) for (j = i + 1; j <= nf; j++) if (fl[j] < fl[i]) { t = fl[i]; fl[i] = fl[j]; fl[j] = t }
	for (i = 1; i <= nf; i++) {
		f = fl[i]; line = "| " f
		for (pi = 1; pi <= 2; pi++) {
			p = pi == 1 ? "iked" : "strongSwan"; cell = ""
			for (gi = 1; gi <= ng; gi++) { key = f SUBSEP p SUBSEP go[gi]
				if (c[key]) cell = cell (cell == "" ? "" : ", ") c[key] " " go[gi] }
			line = line " | " (cell == "" ? "-" : cell)
		}
		print line " |"
	}
}' "$F"
