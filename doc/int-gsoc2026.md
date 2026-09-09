# int/gsoc2026 remaining work

Not a product README. Status vs HEAD `ee0ba74`. Done items stay in NEWS.

## Proven 2026-09-08 22:15

- iked restart left kernel ESP (`0x06c8a0cd` / `0x0428aa74`, NAT-T 4306).
- Load: `resumed IKE_SA … children=1 msgid 0/2`.
- `lastused` 22:15:24 after bounce 22:15:22. iPhone stayed Connected.
- Dump was still FIXY-format; `ike_remain=86400` was the configured fallback, not measured remainder.
- Host reboot is not this. Dump is tmpfs; ESP dies with the kernel.

## In tree

- Resume dump `/var/run/racoon2/resume` (SR2R). Load restores cookies, SK_*, selector. Lifetime dump is wall-clock via `sched_remaining()` (`ee0ba74`).
- RFC 6290 QCD maker in IKE_AUTH; secret `/var/lib/racoon2/qcd.secret` (`StateDirectory=racoon2`). Token-taker crash path untested.
- RFC 4555 COOKIE2 echo (responder). Matrix `ikev2-netns-cookie2` gates `NO_ADDITIONAL_ADDRESSES`. Initiator COOKIE2 not sent.
- RFC 7296 IKE_SA rekey in code. Matrix `ikev2-netns-ikesa-rekey` is a log grep after charon `reauth=no`.
- CHILD hard-expire rekey (`c1aba9d`): skip `lease_list`, match NAT-T `sa_dst` port.

## Still open

1. Second bounce of `ee0ba74`: log `ike_remain=` in the thousands (not 86400), same SPI, phone stays up.
2. `bind 4500 already in use` on restart (iked still bound; harmless so far).
3. Host reboot: persist dump off tmpfs or accept drop. QCD secret already `/var/lib`.
4. RFC 8784 PPK, then 9242/9370 (OpenSSL 3.5+/OQS).
5. IKEv2 EAP-MSCHAPv2 + RADIUS. kinkd vs a live KDC.
6. Transport-mode IKEv2 e2e; IPv6-in-IPv4; Windows/Android/macOS 27.
7. Fuzz `ikev2_input` / `isakmp`.
8. Live IKEv1 NAT-OA peer (matrix `ikev1-strongswan` is negotiation+SAD only).

## Do not

- Bounce live iked with a phone session unless asked.
- Call host reboot or RFC 5723 "resume".
- xxd resume dumps past magic/cookies.
- Ping the CP inner from WSL.
- Push anywhere but `mine`.
