#!/usr/bin/env python3
"""
UPnP IGD port mapping for racoon2 IKE (UDP 500 / IKE NAT-T 4500).

Maps IKE ports on the WAN-facing router NAT to this host so a remote
IKEv2 client (macOS, strongSwan, ...) can reach racoon2 iked/spmd
behind the home router. The real IKE endpoint after `networkingMode=
mirrored` WSL is this Windows host's LAN IPv4, so the mapping target
is the host address, not the WSL vNIC address.

Requirements: `python3 -m pip install miniupnpc`
Works on Windows/Linux/macOS as long as the router exposes an UPnP
IGD and the WiFi/LAN network does not block SSDP discovery.

Usage:
  upnp_portmap.py [--list] [--delete] [--local-ip IP] [--port P] ...
  upnp_portmap.py                     # map UDP 500 and 4500
  upnp_portmap.py --port 500 --port 4500 --download-pbm 0   # same, explicit

Options:
  --local-ip IP    internal client IP for the mapping (default: the
                   host's default-route IPv4, e.g. 192.168.68.79)
  --port P         UDP port to map (repeatable; default 500 4500)
  --lease N        lease seconds (default 0 = permanent where supported)
  --list           show existing mappings and exit
  --delete         remove all racoon2-tagged mappings and exit
  --desc TEXT      mapping description (default "racoon2 IKE UDP <port>")
"""
import argparse
import socket
import sys

try:
    import miniupnpc
except ImportError:
    sys.exit("miniupnpc missing: python3 -m pip install miniupnpc")

DEFAULT_PORTS = (500, 4500)
TAG = "racoon2"


def default_local_ip():
    """IPv4 of the interface used to reach the WAN (like `route get`)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))   # UDP connect: no packets sent
        return s.getsockname()[0]
    finally:
        s.close()


def connect_igd():
    upnp = miniupnpc.UPnP()
    upnp.discoverdelay = 300
    if upnp.discover() == 0:
        sys.exit("no UPnP IGD found on this network (SSDP blocked?)")
    upnp.selectigd()
    print("IGD on %s (external %s)" % (upnp.lanaddr, upnp.wanaddr))
    return upnp


def mapping_key(upnp, idx):
    m = upnp.getportmapping(idx)
    if not m:
        return None
    ext_port, proto, int_port, int_client, desc, lease, enabled = m
    return dict(ext=ext_port, proto=proto, int=int_port,
                client=int_client, enabled=enabled, desc=desc, lease=lease)


def list_mappings(upnp, ports=DEFAULT_PORTS):
    try:
        n = upnp.getportmappingnumberofentries()
    except Exception:
        n = None
    if n is None:
        print("== no port-listing action; checking target ports ==")
        for p in ports:
            m = upnp.getspecificportmapping(p, "UDP")
            if m:
                ext, proto, int_port, int_client, desc, lease, enabled = m
                print("%s/%s -> %s:%s %r lease=%s" % (
                    ext, proto, int_client, int_port, desc, lease))
            else:
                print("%d/udp: no mapping" % p)
        return
    print("== %d mappings ==" % n)
    for i in range(n):
        k = mapping_key(upnp, i)
        if k:
            print("%s/%s -> %s:%s [%s] %r lease=%s" % (
                k["ext"], k["proto"], k["client"], k["int"],
                "on" if k["enabled"] else "off", k["desc"], k["lease"]))


def main():
    ap = argparse.ArgumentParser(description="racoon2 UPnP IGD port mapping")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--delete", action="store_true")
    ap.add_argument("--local-ip", default=None)
    ap.add_argument("--port", type=int, action="append",
                    default=list(DEFAULT_PORTS))
    ap.add_argument("--lease", type=int, default=0)
    ap.add_argument("--desc", default=None)
    args = ap.parse_args()

    if args.local_ip is None:
        args.local_ip = default_local_ip()
    print("local (internal) IP: %s" % args.local_ip)

    upnp = connect_igd()

    if args.list:
        list_mappings(upnp)
        return 0

    if args.delete:
        n = upnp.getportmappingnumberofentries()
        removed = 0
        for i in range(n):
            k = mapping_key(upnp, i)
            if k and k["desc"] and k["desc"].startswith(TAG):
                upnp.deleteportmapping(k["ext"], k["proto"])
                print("deleted %s/%s" % (k["ext"], k["proto"]))
                removed += 1
        print("%d mapping(s) removed" % removed)
        return 0

    for port in args.port:
        desc = args.desc or "%s IKE UDP %d" % (TAG, port)
        try:
            # binding arg order: (eport, proto, rhost, iport, iclient,
            # desc, lease) — miniupnpc >= 2.1 moved iport before iclient
            r = upnp.addportmapping(port, "UDP", "", port, args.local_ip,
                                    desc, args.lease)
        except Exception as e:
            print("IGD REFUSED %d/udp: %s" % (port, e))
            return 1
        if r is None:
            print("mapped %d/udp -> %s:%d (%s)" % (port, args.local_ip,
                                                   port, desc))
        else:
            print("addportmapping %d/udp -> %r (ret=%r)" % (port, desc, r))
            if r != 0:
                return 1

    print("== resulting mappings ==")
    list_mappings(upnp)
    return 0


if __name__ == "__main__":
    sys.exit(main())
