#!/bin/bash
# fwd-nat: add public IP locally + SNAT CP pools out the LAN NIC.
# Run as a systemd oneshot (fwd-nat.service) or hook; uses a private
# nft table so it works alongside WSL's libvirt/nft NAT or Fedora's
# firewalld without fighting over the nat-table owner.
#
# Adjust R2_LAN_IP to the responder's LAN address on the outward NIC,
# and R2_PUB_IP to the router's public (IGD external) address.
R2_LAN_IP="${R2_LAN_IP:-192.168.0.165}"
R2_PUB_IP="${R2_PUB_IP:-65.26.112.134}"

ip addr add "${R2_PUB_IP}/32" dev lo 2>/dev/null || true
set -e
nft delete table ip r2snat 2>/dev/null || true
nft add table ip r2snat
nft add chain ip r2snat postrouting '{ type nat hook postrouting priority 100 ; policy accept ; }'
nft add rule ip r2snat postrouting ip saddr 10.7.73.0/24 ip daddr != 10.7.73.0/24 snat to "${R2_LAN_IP}"
nft add rule ip r2snat postrouting ip saddr 192.0.2.0/24 ip daddr != 192.0.2.0/24 snat to "${R2_LAN_IP}"
echo 1 > /proc/sys/net/ipv4/ip_forward
echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter
echo 0 > /proc/sys/net/ipv4/conf/default/rp_filter
nft list table ip r2snat
echo SNAT-OK
nft add rule ip r2snat postrouting ip saddr 10.8.0.0/24 ip daddr != 10.8.0.0/24 snat to "${R2_LAN_IP}"
