# int/gsoc2026 remaining work

Not a product README. Status vs HEAD. Done items stay in NEWS.

## In tree, not a bounce proof

- Resume dump (`/var/run/racoon2/resume`, SR2R). Load restores cookies, SK_*, selector, remaining IKE lifetime. Not proven: same SPI after iked restart, no INITIAL_CONTACT.
- RFC 6296 QCD maker in IKE_AUTH; secret `/var/lib/racoon2/qcd.secret` (needs `StateDirectory=racoon2`). Token-taker crash path untested.
- RFC 4555 COOKIE2 echo (responder). Matrix `ikev2-netns-cookie2` gates `NO_ADDITIONAL_ADDRESSES`. Initiator COOKIE2 not sent.
- RFC 7296 IKE_SA rekey in code. Matrix `ikev2-netns-ikesa-rekey` is a log grep after charon `reauth=no`.

## Still open

1. Resume bounce: dump → restart iked → `resumed IKE_SA` → same SPI → traffic. Fail that first.
2. Host reboot: dump is tmpfs; QCD secret is `/var/lib`. ESP gone on reboot.
3. RFC 8784 PPK, then 9242/9370 (OpenSSL 3.5+/OQS).
4. IKEv2 EAP-MSCHAPv2 + RADIUS. kinkd vs a live KDC.
5. Transport-mode IKEv2 e2e; IPv6-in-IPv4; Windows/Android/macOS 27.
6. Fuzz ikev2_input / isakmp.
7. Live IKEv1 NAT-OA peer (matrix `ikev1-strongswan` is negotiation+SAD only).

## Do not

- Bounce live iked with a phone session unless asked.
- Treat dump-only resume as connectful.
- xxd resume dumps past magic/cookies.
