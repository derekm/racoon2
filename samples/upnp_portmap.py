#!/usr/bin/env python3
"""
UPnP IGD port mapping for racoon2 IKE (UDP 500 / IKE NAT-T 4500).

Maps IKE ports on the WAN-facing router NAT to this host so a remote
IKEv2 client (macOS, strongSwan, ...) can reach racoon2 iked/spmd
behind the home router. The real IKE endpoint after `networkingMode=
mirrored` WSL is this Windows host's LAN IPv4, so the mapping target
is the host address, not the WSL vNIC address.

Requirements: Python 3 stdlib only; miniupnpc (when importable) gives
cleaner devices, but Linux/BSD/macOS/Windows all fall back to a raw
SOAP WANIPConnection conduit implemented here, plus NAT-PMP UDP/5351.
Windows additionally uses HNetCfg.NATUPnP for permanent mappings.
Some IGDs answer SSDP and list mappings but SOAP AddPortMapping
returns Action Failed (this home gateway does). UDP 500 is not blocked
as a reserved port on this IGD via those paths. Mapping target is the
host's default-route IPv4 (Windows LAN IP, not the WSL vNIC).

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
import time

try:
    import miniupnpc
    _HAVE_MINIUPNPC = True
except ImportError:
    _HAVE_MINIUPNPC = False

import re
import urllib.request
import urllib.parse

DEFAULT_PORTS = (500, 4500)
TAG = "racoon2"
SOAP_NS = "urn:schemas-upnp-org:service:WANIPConnection:1"
SSDP_ADDR = ("239.255.255.250", 1900)


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
    # Linux/BSD/macOS: parse `ip route` (Linux) then `netstat -rn`.
    try:
        out = subprocess.check_output(
            ["ip", "route", "show", "default"], text=True,
            stderr=subprocess.DEVNULL)
        toks = out.split()
        if "via" in toks:
            return toks[toks.index("via") + 1]
    except Exception:
        pass
    try:
        out = subprocess.check_output(
            ["netstat", "-rn"], text=True, errors="replace")
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] in ("0.0.0.0", "default"):
                if len(parts) >= 4 and parts[1].count(".") == 3:
                    return parts[1]
                if len(parts) >= 2 and parts[1].count(".") == 3:
                    return parts[1]
    except Exception:
        pass
    # Last resort: heuristics on the default-route interface address.
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


class RawIGD:
    """Stdlib-only UPnP IGD: SSDP discovery + SOAP/XML calls.

    Mirrors the tiny slice of the miniupnpc API this script uses
    (lanaddr/wanaddr/discover/selectigd/getgenericportmapping/
    getspecificportmapping/getportmappingnumberofentries/
    addportmapping/deleteportmapping) so no third-party module is
    needed on Linux/BSD/macOS or even Windows.
    """

    def __init__(self):
        self.lanaddr = None
        self.wanaddr = None
        self._ctrl_url = None
        self._desc = None

    # -- discovery ---------------------------------------------------
    def _msearch(self, st, timeout=4):
        msg = ("M-SEARCH * HTTP/1.1\r\n"
               "HOST: %s\r\n"
               "MAN: \"ssdp:discover\"\r\n"
               "MX: 3\r\n"
               "ST: %s\r\n\r\n")
        locations = set()
        # Unicast to the default gateway first: firewalld/nft conntrack
        # treats the reply as established, while multicast replies come
        # from a different source IP and get dropped as NEW on Linux.
        gw = default_gateway()
        if gw:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            try:
                s.sendto((msg % ("%s:1900" % gw, st)).encode(), (gw, 1900))
                end = time.monotonic() + timeout
                while time.monotonic() < end:
                    try:
                        data, addr = s.recvfrom(4096)
                    except socket.timeout:
                        break
                    head = data.decode("utf-8", "replace")
                    for line in head.splitlines():
                        if line.lower().startswith("location:"):
                            locations.add(line.split(":", 1)[1].strip())
            finally:
                s.close()
            if locations:
                return sorted(locations)
        # Multicast SSDP as a fallback (works without a gateway route).
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        s.settimeout(timeout)
        try:
            s.sendto((msg % ("239.255.255.250:1900", st)).encode(),
                     SSDP_ADDR)
            end = time.monotonic() + timeout
            while time.monotonic() < end:
                try:
                    data, addr = s.recvfrom(4096)
                except socket.timeout:
                    break
                head = data.decode("utf-8", "replace")
                for line in head.splitlines():
                    if line.lower().startswith("location:"):
                        locations.add(line.split(":", 1)[1].strip())
        finally:
            s.close()
        return sorted(locations)

    def discover(self):
        # device-level discovery first, then answer-agnostic re-query
        try:
            for loc in self._msearch(
                    "urn:schemas-upnp-org:device:InternetGatewayDevice:1"):
                if self._load(loc):
                    self.lanaddr = default_local_ip()
                    return 1
        except Exception:
            pass
        try:
            for loc in self._msearch(
                    "urn:schemas-upnp-org:device:WANConnectionDevice:1"):
                if self._load(loc):
                    self.lanaddr = default_local_ip()
                    return 1
        except Exception:
            pass
        return 0

    def _load(self, loc):
        try:
            with urllib.request.urlopen(loc, timeout=5) as r:
                xml = r.read().decode("utf-8", "replace")
        except Exception:
            return False
        self._desc = loc
        if "WANIPConnection" not in xml and "WANPPPConnection" not in xml:
            return False
        m = re.search(
            r"<serviceType>urn:schemas-upnp-org:service:"
            r"WAN(?:IP|PPP)Connection:1</serviceType>"
            r"[\s\S]*?<controlURL>([^<]+)</controlURL>", xml)
        if not m:
            return False
        self._ctrl_url = urllib.parse.urljoin(loc, m.group(1))
        return True

    def selectigd(self):
        if not self._ctrl_url:
            raise RuntimeError("no IGD selected")

    def _soap(self, action, kwargs=None):
        if not self._ctrl_url:
            raise RuntimeError("no IGD selected")
        args = ""
        for k, v in (kwargs or {}).items():
            args += "<{0}>{1}</{0}>".format(
                k, str(v).replace("&", "&amp;").replace("<", "&lt;"))
        body = ('<?xml version="1.0"?>'
                '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
                's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
                '<s:Body><u:%s xmlns:u="%s">%s</u:%s></s:Body></s:Envelope>'
                % (action, SOAP_NS, args, action))
        req = urllib.request.Request(
            self._ctrl_url,
            data=body.encode("utf-8"),
            headers={
                "Content-Type": 'text/xml; charset="utf-8"',
                "SOAPAction": '"%s#%s"' % (SOAP_NS, action),
                "User-Agent": "racoon2-upnp_portmap",
            },
            method="POST")
        with urllib.request.urlopen(req, timeout=6) as r:
            return r.read().decode("utf-8", "replace")

    def _find(self, text, tag):
        m = re.search(r"<%s>([^<]*)</%s>" % (tag, tag), text)
        return m.group(1) if m else None

    # -- mapping API (miniupnpc-compatible) --------------------------
    def getgenericportmapping(self, idx):
        try:
            xml = self._soap("GetGenericPortMappingEntry",
                             {"NewPortMappingIndex": idx})
        except Exception:
            return None
        if "errorCode" in xml:          # 713 = no such entry
            return None
        keys = ("NewRemoteHost", "NewExternalPort", "NewProtocol",
                "NewInternalPort", "NewInternalClient", "NewEnabled",
                "NewPortMappingDescription", "NewLeaseDuration")
        vals = [self._find(xml, k) for k in keys]
        if any(v is None for v in vals):
            return None
        return (int(vals[1]), vals[2],
                (vals[4], int(vals[3])),
                vals[6], vals[5].lower() in ("1", "true", "yes"),
                vals[0], int(vals[7]))

    def getportmappingnumberofentries(self):
        try:
            xml = self._soap("GetPortMappingNumberOfEntries")
            n = self._find(xml, "NewPortMappingNumberOfEntries")
            if n is None:
                raise RuntimeError("no count in reply")
            return int(n)
        except Exception:
            raise

    def getspecificportmapping(self, eport, proto):
        try:
            xml = self._soap("GetSpecificPortMappingEntry", {
                "NewRemoteHost": "", "NewExternalPort": eport,
                "NewProtocol": proto})
        except Exception:
            return None
        if "errorCode" in xml:
            return None
        keys = ("NewInternalClient", "NewInternalPort", "NewEnabled",
                "NewPortMappingDescription", "NewLeaseDuration")
        vals = [self._find(xml, k) for k in keys]
        if any(v is None for v in vals):
            return None
        return (vals[0], int(vals[1]), vals[3], vals[2], int(vals[4]))

    def addportmapping(self, eport, proto, rhost, iport, iclient,
                       desc, lease=0, enabled=1):
        if rhost is None:
            rhost = ""
        xml = self._soap("AddPortMapping", {
            "NewRemoteHost": rhost, "NewExternalPort": eport,
            "NewProtocol": proto, "NewInternalPort": iport,
            "NewInternalClient": iclient, "NewEnabled": enabled,
            "NewPortMappingDescription": desc,
            "NewLeaseDuration": lease})
        return None if "errorCode" not in xml else int(
            re.search(r"<errorCode>(\d+)</errorCode>", xml).group(1))

    def deleteportmapping(self, eport, proto, rhost=""):
        xml = self._soap("DeletePortMapping", {
            "NewRemoteHost": rhost, "NewExternalPort": eport,
            "NewProtocol": proto})
        m = re.search(r"<errorCode>(\d+)</errorCode>", xml)
        if m:
            raise RuntimeError("DeletePortMapping %s/%s failed "
                               "(errorCode %s)" % (eport, proto, m.group(1)))

    def external_ip(self):
        xml = self._soap("GetExternalIPAddress")
        return self._find(xml, "NewExternalIPAddress")


def connect_igd():
    if _HAVE_MINIUPNPC:
        try:
            upnp = miniupnpc.UPnP()
            upnp.discoverdelay = 300
            if upnp.discover() > 0:
                upnp.selectigd()
                print("IGD on %s (external %s)" % (upnp.lanaddr,
                                                   upnp.wanaddr))
                return upnp
            print("miniupnpc found no device; trying raw SOAP")
        except Exception as e:
            print("miniupnpc unusable (%s); trying raw SOAP" % e)
    igd = RawIGD()
    if igd.discover() == 0:
        sys.exit("no UPnP IGD found on this network (SSDP blocked?)")
    igd.selectigd()
    ext = igd.external_ip()
    print("IGD SOAP on %s (external %s)" % (igd.lanaddr, ext))
    return igd


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
            if k["desc"] and k["client"] == args.local_ip and (
                    k["desc"].startswith(TAG) or
                    "NAT-PMP %s udp" % k["ext"] in k["desc"]):
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
