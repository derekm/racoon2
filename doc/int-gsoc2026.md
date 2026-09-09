# int/gsoc2026 remaining work

Not a product README. Status vs HEAD. Done items stay in NEWS.

## Proven 2026-09-08

- iked restart left kernel ESP (`0x06c8a0cd` / `0x0428aa74`). iPhone stayed Connected. `lastused` after bounce.
- Second bounce: save/load `ike_remain=85351` (wall-clock, not 1, not 86400).
- Dump was FIXY on the first bounce (`ike_remain=86400` fallback).

## In tree

- Resume dump `/var/lib/racoon2/resume` (SR2R, StateDirectory). Wall-clock lifetime. If dump mtime predates boot, CHILD rekey in 1s (kernel ESP gone). Not proven across a host reboot.
- RFC 6290 QCD maker in IKE_AUTH; secret `/var/lib/racoon2/qcd.secret`. Token-taker untested.
- RFC 4555 COOKIE2 echo (responder). Matrix `ikev2-netns-cookie2` gates `NO_ADDITIONAL_ADDRESSES`.
- RFC 7296 IKE_SA rekey in code. Matrix row is a log grep after charon `reauth=no`.
- CHILD hard-expire rekey (`c1aba9d`). Live 3600s iPhone rekey not watched (ESP was gone by 22:38).

## Still open

1. Host reboot with a live dump: load logs `kernel ESP gone, CHILD rekey 1s`, phone stays or briefly blips. Gap during boot still possible.
2. Live CHILD rekey on iPhone (~48 min soft / 3600s hard).
3. `bind 4500 already in use` on restart.
4. RFC 8784 PPK, then 9242/9370 (OpenSSL 3.5+/OQS).
5. IKEv2 EAP-MSCHAPv2 + RADIUS. kinkd vs a live KDC.
6. Transport-mode IKEv2 e2e; IPv6-in-IPv4; Windows/Android/macOS 27.
7. Fuzz `ikev2_input` / `isakmp`.
8. Live IKEv1 NAT-OA peer.

## Do not

- Bounce live iked with a phone session unless asked.
- Call host reboot or RFC 5723 "resume" until measured.
- xxd resume dumps past magic/cookies.
- Ping the CP inner from WSL.
- Push anywhere but `mine`.
