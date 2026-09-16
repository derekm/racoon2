#!/bin/bash
# iked-pre: load the XFRM crypto pieces iked needs, SNAT for CP pools.
# ExecStartPre for iked.service; idempotent (systemd reruns it on restart).
#
# ESP AES-CBC+HMAC needs the authenc template (CONFIG_CRYPTO_AUTHENC=m);
# without it XFRM ADD returns ENOENT /
# "unable to initialize cryptographic operations".
R2_LAN_IP="${R2_LAN_IP:-192.168.68.119}"

modprobe xfrm_user || true
modprobe esp4 || true
modprobe authenc || true
modprobe echainiv || true   # absent on some 6.x/7.x kernels — tolerated
# nft SNAT in a private table (iptables MASQUERADE cannot join the
# owner's nat table on WSL/fercewall hosts).
nft list table ip r2snat >/dev/null 2>&1 || {
  nft add table ip r2snat
  nft add chain ip r2snat postrouting '{ type nat hook postrouting priority 100 ; policy accept ; }'
  nft add rule ip r2snat postrouting ip saddr 10.7.73.0/24 ip daddr != 10.7.73.0/24 snat to "${R2_LAN_IP}"
  nft add rule ip r2snat postrouting ip saddr 192.0.2.0/24 ip daddr != 192.0.2.0/24 snat to "${R2_LAN_IP}"
}
echo 1 > /proc/sys/net/ipv4/ip_forward
lsmod | grep -E '^authenc|^esp4|^xfrm_user' || true
echo PRE-OK
