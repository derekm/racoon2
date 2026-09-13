# int/gsoc2026 remaining work

Not a product README. Status vs HEAD. Done items stay in NEWS.

## Proven 2026-09-12 (`41124dd` live)

- Initiated CHILD rekey: new SAs installed, old deleted (RFC 7296 §2.8).
- Same MainPID **1423482** through +480s rekey **and** 10-min UPDATE_SA/DPD. ESP grew. No SEGV.
- 18:20 drop: `ikev2_destroy_child_sa` `selector->next` on a selector-less informational dummy (offset 0x40).

## In tree

- NATD replies: SRC=local, DST=remote (RFC 7296 §2.23 / 4555 §3.8).
- msgid as original responder is **0** (RFC 7296 §2.2). `ikev2-netns-r2rekey` is the charon proof (GitHub CI, do not run locally against a phone).
- `ikev2_child_rekey_floor` default **0** (off) so iOS can initiate ~1440s. Positive value caps CP children only.
- Resume dump v2 stores child ENCR/INTEGR/ESN.
- Payload walk after DELETE continues unless IKE_SA aborted.

## Still this chunk (do not start EAP/8784)

1. iOS-initiated CHILD rekey (~1440s). Lease move is the claimed `ts unacceptable` fix. Unproven until a session with floor=0 lives that long.
2. One 3600s hard cycle, same pid, ESP still moving.
3. Host reboot with a live dump. `bind 4500 already in use` on restart.

## Later

- IKEv2 EAP-MSCHAPv2 + RADIUS.
- QCD token-taker. RFC 8784 PPK after OpenSSL ≥3.5/OQS.
- Transport-mode IKEv2 e2e; IPv6-in-IPv4; Windows/Android/macOS.
- Fuzz `ikev2_input` / `isakmp`. Live IKEv1 NAT-OA peer.

## Do not

- Bounce live iked with a phone session unless asked.
- Call host reboot or RFC 5723 "resume" until measured.
- xxd resume dumps past magic/cookies.
- Ping the CP inner from WSL.
- Push anywhere but `mine`.
- Run linux-matrix IKE rows (workers=0) against a live phone session.
