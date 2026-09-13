# int/gsoc2026 remaining work

Not a product README. Status vs HEAD. Done items stay in NEWS.

## Proven 2026-09-12 (`41124dd` live)

- Initiated CHILD rekey (480s CP floor): new SAs installed, old deleted (RFC 7296 §2.8).
- Same MainPID **1423482** through +480s rekey **and** 10-min UPDATE_SA/DPD. ESP counters grew after both. No SEGV.
- Root of the 18:20 drop: `ikev2_destroy_child_sa` did `selector->next` on a selector-less informational dummy (offset 0x40), GC'd by the 3s periodic task.

## In tree (not all deployed)

- NATD on INFORMATIONAL/CREATE_CHILD replies: SRC=local, DST=remote (RFC 7296 §2.23 / 4555 §3.8). Not a peer-digest echo.
- msgid mint as original responder is **2** (Apple interop). RFC 7296 §2.2 says 0. Cited honestly; charon RFC-0 untested.
- `IKEV2_CHILD_REKEY_FLOOR` 480s applies only to CP/road-warrior (`lease_list` non-empty).
- Resume dump v2 stores child ENCR/INTEGR/ESN so rekey clones the live suite, not config[0] GCM.
- Payload walk after DELETE continues unless the IKE_SA was aborted.

## Still this chunk (do not start EAP/8784)

1. iOS-initiated CHILD rekey (~1440s after our rekey). Lease move is the claimed `ts unacceptable` fix. Unproven.
2. One 3600s hard cycle, same pid, ESP still moving.
3. Matrix: racoon2-initiated CHILD rekey as original responder vs charon (`rekey=no` on charon). Existing `ikev2-netns-childrekey` is charon-initiated PFS-19, no CP, no msgid mint.
4. msgid 0 vs charon (RFC §2.2) once the SA body is known-good.
5. Host reboot with a live dump. `bind 4500 already in use` on restart.

## Later

- IKEv2 EAP-MSCHAPv2 + RADIUS (next protocol-plane gap vs the vendor matrix).
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
