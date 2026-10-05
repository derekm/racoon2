#!/usr/bin/env python3
"""Capture and re-inject IKEv2 frames on a veth (linux-matrix fault tool).

  ikeframes.py capture IFACE OUTFILE [--src IP] [--exch N] [--skf]
      Sniff IPv4/UDP frames to port 500/4500 on IFACE (AF_PACKET)
      and append each matching IKEv2 frame to OUTFILE as one hex line:
      "<msgid> <exch> <flags> <first_payload> <src> <frame-hex>".  --src keeps
      only frames from that source address, --exch only that exchange
      type, --skf only frames whose first payload is SKF (53).  Runs
      until killed; every line is flushed as it is written.

  ikeframes.py send IFACE INFILE --msgid N [--exch N] [--src IP]
      Re-send every captured frame with that message id (and exchange
      type, source) out of IFACE (AF_PACKET, below IP and XFRM).  The IKE
      message is sent byte for byte; only the IPv4/UDP checksums, which
      veth leaves to offload, are recomputed.
      Prints the number of frames sent.
"""
import argparse
import socket
import struct
import sys

ETH_P_ALL = 0x0003
ETH_P_IP = 0x0800


def parse_ike(frame):
    """Return (msgid, exch, flags, first_payload, src) or None."""
    if len(frame) < 14 + 20 + 8 + 28:
        return None
    if struct.unpack('!H', frame[12:14])[0] != ETH_P_IP:
        return None
    ip = frame[14:]
    ihl = (ip[0] & 0x0f) * 4
    if ip[9] != 17:
        return None
    src = socket.inet_ntoa(ip[12:16])
    udp = ip[ihl:]
    sport, dport = struct.unpack('!HH', udp[0:4])
    ike = udp[8:]
    if dport == 4500 or sport == 4500:
        if ike[:4] != b'\0\0\0\0':
            return None          # ESP-in-UDP, not IKE
        ike = ike[4:]
    elif dport != 500:
        return None
    if len(ike) < 28:
        return None
    first_payload = ike[16]
    exch = ike[18]
    flags = ike[19]
    msgid = struct.unpack('!I', ike[20:24])[0]
    return msgid, exch, flags, first_payload, src


def csum(b):
    if len(b) % 2:
        b += b'\0'
    t = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while t >> 16:
        t = (t & 0xffff) + (t >> 16)
    return ~t & 0xffff


def fix_checksums(frame):
    """veth hands AF_PACKET frames with offloaded (partial) checksums;
    recompute the IPv4 header and UDP checksums so the re-sent frame is
    accepted.  The IKE bytes are not touched."""
    f = bytearray(frame)
    ip = 14
    ihl = (f[ip] & 0x0f) * 4
    tot = struct.unpack('!H', f[ip + 2:ip + 4])[0]
    f[ip + 10:ip + 12] = b'\0\0'
    f[ip + 10:ip + 12] = struct.pack('!H', csum(bytes(f[ip:ip + ihl])))
    u = ip + ihl
    ulen = tot - ihl
    f[u + 6:u + 8] = b'\0\0'
    pseudo = bytes(f[ip + 12:ip + 20]) + struct.pack('!BBH', 0, 17, ulen)
    c = csum(pseudo + bytes(f[u:u + ulen]))
    f[u + 6:u + 8] = struct.pack('!H', c or 0xffff)
    return bytes(f[:ip + tot])


def capture(a):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    s.bind((a.iface, 0))
    with open(a.outfile, 'a') as out:
        while True:
            frame, addr = s.recvfrom(65535)
            r = parse_ike(frame)
            if r is None:
                continue
            msgid, exch, flags, fp, src = r
            if a.src and src != a.src:
                continue
            if a.exch is not None and exch != a.exch:
                continue
            if a.skf and fp != 53:
                continue
            out.write('%d %d %d %d %s %s\n' % (msgid, exch, flags, fp, src, frame.hex()))
            out.flush()


def send(a):
    frames = []
    with open(a.infile) as f:
        for line in f:
            p = line.split()
            if len(p) != 6:
                continue
            if int(p[0]) != a.msgid:
                continue
            if a.exch is not None and int(p[1]) != a.exch:
                continue
            if a.src and p[4] != a.src:
                continue
            frames.append(bytes.fromhex(p[5]))
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((a.iface, 0))
    for fr in frames:
        s.send(fix_checksums(fr))
    print(len(frames))


def main():
    ap = argparse.ArgumentParser()
    sp = ap.add_subparsers(dest='cmd', required=True)
    c = sp.add_parser('capture')
    c.add_argument('iface')
    c.add_argument('outfile')
    c.add_argument('--src')
    c.add_argument('--exch', type=int)
    c.add_argument('--skf', action='store_true')
    s = sp.add_parser('send')
    s.add_argument('iface')
    s.add_argument('infile')
    s.add_argument('--msgid', type=int, required=True)
    s.add_argument('--exch', type=int)
    s.add_argument('--src')
    a = ap.parse_args()
    if a.cmd == 'capture':
        capture(a)
    else:
        send(a)
    return 0


if __name__ == '__main__':
    sys.exit(main())
