#!/usr/bin/env python3
# xfrm_migrate_probe.py: does this kernel implement XFRM_MSG_MIGRATE?
# Sends an XFRM_MSG_MIGRATE with no XFRMA_MIGRATE attribute (it can move
# nothing).  A kernel built without CONFIG_XFRM_MIGRATE answers
# ENOPROTOOPT; one with it rejects the empty request (EINVAL/ENOENT).
# Exit 0 + message: migrate absent (proof).  Exit 1: present.  Exit 2:
# could not tell.  Run inside a private netns.
import errno, os, socket, struct, sys
NETLINK_XFRM = 6
XFRM_MSG_MIGRATE = 0x21
NLM_F_REQUEST, NLM_F_ACK = 1, 4
NLMSG_ERROR = 2
body = b'\0' * 64          # struct xfrm_userpolicy_id
hdr = struct.pack('=LHHLL', 16 + len(body), XFRM_MSG_MIGRATE,
                  NLM_F_REQUEST | NLM_F_ACK, 1, 0)
try:
    s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_XFRM)
    s.bind((0, 0))
    s.settimeout(3)
    s.send(hdr + body)
    r = s.recv(4096)
except OSError as e:
    print("probe error: %s" % e); sys.exit(2)
ln, typ = struct.unpack('=LH', r[:6])
if typ != NLMSG_ERROR:
    print("unexpected reply type %d" % typ); sys.exit(2)
err = -struct.unpack('=i', r[16:20])[0]
if err == errno.ENOPROTOOPT:
    print("XFRM_MSG_MIGRATE -> ENOPROTOOPT: kernel %s built without CONFIG_XFRM_MIGRATE" % os.uname().release)
    sys.exit(0)
print("XFRM_MSG_MIGRATE -> %s (implemented)" % (errno.errorcode.get(err, err) if err else 0))
sys.exit(1)
