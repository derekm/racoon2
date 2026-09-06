#!/usr/bin/env python3
"""
UPnP IGD port mapping for racoon2 IKE (UDP 500 / IKE NAT-T 4500).

Maps IKE ports on the WAN-facing router NAT to this host so a remote
IKEv2 client (macOS, strongSwan, ...) can reach racoon2 iked/spmd
behind the home router. The real IKE endpoint after `networkingMode=
mirrored` WSL is this Windows host's LAN IPv4, so the mapping target
is the host address, not the WSL vNIC address.

Requirements: `python3 -m pip install miniupnpc`
Some IGDs answer SSDP and list mappings but SOAP AddPortMapping
returns Action Failed (this home gateway does). Fallback: Windows
`HNetCfg.NATUPnP` (permanent) then NAT-PMP UDP/5351 (1h lease).
UDP 500 is not blocked as a reserved port on this IGD via those
paths. Mapping target is the Windows LAN IPv4, not the WSL vNIC.

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
import struct
import subprocess
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


def default_gateway():
    """IPv4 default gateway (NAT-PMP / PCP endpoint)."""
    if sys.platform == "win32":
        out = subprocess.check_output(
            "route print -4", shell=True, text=True, errors="replace")
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[0] == "0.0.0.0":
                return parts[2]
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ".".join(ip.split(".")[:3] + ["1"])


def natpmp_map(gw, port, lifetime=3600):
    """NAT-PMP UDP map. result 0 = ok. lifetime 0 deletes."""
    pkt = struct.pack("!BBHHHI", 0, 1, 0, port, port, lifetime)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    try:
        s.sendto(pkt, (gw, 5351))
        data, _ = s.recvfrom(32)
    finally:
        s.close()
    if len(data) < 16:
        raise RuntimeError("NAT-PMP short reply %r" % data)
    ver, op, result, epoch, iport, eport, life = struct.unpack("!BBHIHHI", data[:16])
    if result != 0:
        raise RuntimeError("NAT-PMP result %d" % result)
    return eport, life


def win_com_map(port, local_ip, desc):
    """Windows IGD via HNetCfg.NATUPnP (lease 0 on this gateway)."""
    d = desc.replace("'", "''")
    ps = (
        "$n = New-Object -ComObject HNetCfg.NATUPnP; "
        "$c = $n.StaticPortMappingCollection; "
        "if ($c -eq $null) { throw 'StaticPortMappingCollection is null' }; "
        "try { $c.Remove(%d, 'UDP') } catch {}; "
        "$c.Add(%d, 'UDP', %d, '%s', $true, '%s')"
        % (port, port, port, local_ip, d)
    )
    subprocess.check_call(
        ["powershell.exe", "-NoProfile", "-Command", ps + " | Out-Null"])


def connect_igd():
    upnp = miniupnpc.UPnP()
    upnp.discoverdelay = 300
    if upnp.discover() == 0:
        sys.exit("no UPnP IGD found on this network (SSDP blocked?)")
    upnp.selectigd()
    print("IGD on %s (external %s)" % (upnp.lanaddr, upnp.wanaddr))
    return upnp


def mapping_key(upnp, idx):
    try:
        m = upnp.getgenericportmapping(idx)
    except Exception:
        m = None
    if not m:
        return None
    # (eport, proto, (iclient, iport), desc, enabled, rhost, lease)
    ext_port, proto, client, desc, enabled, rhost, lease = m
    int_client, int_port = client
    return dict(ext=ext_port, proto=proto, int=int_port,
                client=int_client, enabled=enabled, desc=desc, lease=lease)


def list_mappings(upnp, ports=DEFAULT_PORTS):
    print("== mappings ==")
    seen = False
    for i in range(32):
        k = mapping_key(upnp, i)
        if not k:
            continue
        seen = True
        print("%s/%s -> %s:%s [%s] %r lease=%s" % (
            k["ext"], k["proto"], k["client"], k["int"],
            "on" if k["enabled"] else "off", k["desc"], k["lease"]))
    if seen:
        return
    print("== no port-listing action; checking target ports ==")
    for p in ports:
        m = upnp.getspecificportmapping(p, "UDP")
        if m:
            int_client, int_port, desc, enabled, lease = m[:5]
            print("%d/udp -> %s:%s %r lease=%s enabled=%s" % (
                p, int_client, int_port, desc, lease, enabled))
        else:
            print("%d/udp: no mapping" % p)


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
        n = 0
        try:
            n = upnp.getportmappingnumberofentries() or 0
        except Exception:
            n = 32
        removed = 0
        gw = default_gateway()
        for i in range(n):
            k = mapping_key(upnp, i)
            if not k:
                continue
            if k["desc"] and (k["desc"].startswith(TAG) or "NAT-PMP %s udp" % k["ext"] in (k["desc"] or "") and k["client"] == args.local_ip):
                try:
                    upnp.deleteportmapping(k["ext"], k["proto"])
                except Exception:
                    if k["proto"] == "UDP":
                        natpmp_map(gw, k["ext"], lifetime=0)
                print("deleted %s/%s" % (k["ext"], k["proto"]))
                removed += 1
        print("%d mapping(s) removed" % removed)
        return 0

    gw = default_gateway()
    for port in args.port:
        desc = args.desc or "%s IKE UDP %d" % (TAG, port)
        mapped = False
        try:
            # binding arg order: (eport, proto, rhost, iport, iclient,
            # desc, lease) — miniupnpc >= 2.1 moved iport before iclient
            r = upnp.addportmapping(port, "UDP", "", port, args.local_ip,
                                    desc, args.lease)
            if r in (None, 0):
                print("SOAP mapped %d/udp -> %s:%d (%s)" % (
                    port, args.local_ip, port, desc))
                mapped = True
            else:
                print("SOAP addportmapping %d/udp ret=%r" % (port, r))
        except Exception as e:
            print("SOAP REFUSED %d/udp: %s" % (port, e))

        if not mapped and sys.platform == "win32":
            try:
                win_com_map(port, args.local_ip, desc)
                print("COM mapped %d/udp -> %s:%d (%s)" % (
                    port, args.local_ip, port, desc))
                mapped = True
            except Exception as e:
                print("COM REFUSED %d/udp: %s" % (port, e))

        if not mapped:
            try:
                life = args.lease if args.lease > 0 else 3600
                eport, life = natpmp_map(gw, port, lifetime=life)
                print("NAT-PMP mapped %d/udp -> %s:%d lease=%s" % (
                    eport, args.local_ip, port, life))
                mapped = True
            except Exception as e:
                print("NAT-PMP REFUSED %d/udp: %s" % (port, e))

        if not mapped:
            print("IGD REFUSED %d/udp on SOAP, COM, and NAT-PMP" % port)
            return 1

    print("== resulting mappings ==")
    list_mappings(upnp)
    return 0


if __name__ == "__main__":
    sys.exit(main())
