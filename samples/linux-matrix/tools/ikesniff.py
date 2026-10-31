#!/usr/bin/env python3
# ikesniff.py <ifname> <local-ipv4> <out.tsv>
# Wire recorder for matrix rows: logs every IKEv2 datagram (UDP 500, or
# UDP 4500 with the RFC 3948 zero marker) seen on <ifname> until SIGTERM.
# One TSV line per message:
#   dir(out|in) exch first-payload ispi rspi flags msgid udp-len
# so a row can gate on wire facts (SKF payload 53 for RFC 7383, exchange
# 36/37 for rekey/DELETE, a new IKE SPI pair after an IKE_SA rekey)
# instead of daemon log wording.  Needs only python3 + AF_PACKET; run it
# inside the row's private netns.
import signal, socket, struct, sys

ifn, local, out = sys.argv[1], socket.inet_aton(sys.argv[2]), sys.argv[3]
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
s.bind((ifn, 0))
f = open(out, "w", buffering=1)
signal.signal(signal.SIGTERM, lambda *a: sys.exit(0))
while True:
    pkt, addr = s.recvfrom(65535)
    if len(pkt) < 14 + 20 + 8 or pkt[12:14] != b"\x08\x00":
        continue
    ip = pkt[14:]
    ihl = (ip[0] & 15) * 4
    if ip[9] != 17 or len(ip) < ihl + 8:
        continue
    src, dst = ip[12:16], ip[16:20]
    sport, dport, ulen = struct.unpack("!HHH", ip[ihl:ihl + 6])
    pl = ip[ihl + 8:]
    if 4500 in (sport, dport):
        if len(pl) < 4 or pl[:4] != b"\0\0\0\0":
            continue          # ESP-in-UDP or keepalive
        pl = pl[4:]
    elif 500 not in (sport, dport):
        continue
    if len(pl) < 28 or (pl[17] >> 4) != 2:
        continue
    d = "out" if src == local else "in" if dst == local else "?"
    f.write("%s\t%d\t%d\t%s\t%s\t0x%02x\t%d\t%d\n" % (
        d, pl[18], pl[16], pl[0:8].hex(), pl[8:16].hex(), pl[19],
        struct.unpack("!I", pl[20:24])[0], ulen))
