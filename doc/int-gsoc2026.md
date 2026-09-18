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
- Shared child PFS gate `ikev2_child_dhdef()`: responder no longer
  borrows the IKE SA's DH group for a DH-less proposal (that sent
  KEr + g^ir for a PFS-less suite; iOS killed the IKE_SA one
  message after the first iOS-initiated rekey, 20:01:34).  Both
  paths gate on "proposal carries a DH transform" (RFC 7296 §2.18).

## Build & deploy
- Top-level `make install` (after `./configure && make`) is the only
  documented path: it recurses through `SUBDIRS = lib spmd kinkd iked
  ...`, installing `libracoon` before `iked`.
- Per-directory installs are off the documented path. `make -C iked
  install` alone leaves a stale `/usr/local/racoon2/lib/libracoon.so`
  behind and the new iked silently links the old library at runtime
  (2026-09-14: 10:50 lib + 21:17 iked, duplicate journal lines until
  lib was reinstalled). If a per-dir install is ever done, `lib` must
  go first: `make -C lib install && make -C iked install`.
- Restart the service after install: `systemctl restart racoon2-iked`.
- Verify the running binary actually has the change:
  `md5sum /usr/local/racoon2/lib/libracoon.so.0.0.0
  /mnt/.../racoon2/lib/.libs/libracoon.so.0.0.0` must match (same for
  `sbin/iked` vs `iked/.libs/iked`).

## Proven by the 2026-09-14/15 13h session (journal-verified)

Phone (67.37.10.151, LTE) ESTABLISHED 19:32:21 → 08:29:07 (13h), across
**four iked restarts** (21:17 maintenance bounce + 3 rebounces, 01:03):
every restart was a clean SIGTERM with resume save/restore of the same
IKE_SA (`restore_one ... 67.37.10.151[6688]`, declining ike_remain); only
**2 INITIAL_CONTACT** in 13h = iOS never re-authenticated, tunnel stayed
continuous through daemon restarts. **110 IKE_SA rekeys + 110 ESP rekey
pairs** (3600s hard cycle + iOS-initiated ~1440s cadence) ran repeatedly
on the same PID. Plan items "show a 3600s cycle, same pid, ESP moving"
and "host reboot with live dump" are covered — **except** the PFS-gate
rekey confirmation on the current (post-`f7f3b8a`) binary, which still
needs its own live session. Note: this session predates today's fixes;
re-verify on the new Fedora server.

## RFC 9370 ADDKE / ML-KEM — landed 2026-09-18

- Responder **child** rekey ADDKE (type-6 in MINE → echo + 16441 → responder
  IKE_FOLLOWUP_KE → deferred child install) and **IKE_SA-rekey** responder feed;
  initiator **child** ADDKE; reverse-pass proposal skip; resume skips
  incomplete-keymat children; teardown zeroizes keymat. Config
  `esp_addke_alg { mlkem768; };`, `--enable-addke` (OpenSSL ≥3.5), live on Fedora
  `16372b2` (NRestarts=0).
- Independent pin: `addkekat` replays NIST FIPS 203 KATs — **20/20** shipped,
  **1000/1000** full file, suite **7/7**; log in `doc/kattest-results.txt`.
- Full write-up: `doc/addke-design.md` (inventory, gaps, decision criteria).

**Still open within 9370:** initiator IKE_SA-rekey ADDKE feed; outbound
fragmentation of our IKE_FOLLOWUP_KE (KE ≈1192 B can exceed a small MTU in the
initiator role); and the **live completed ADDKE child rekey** on a crash-free
daemon — the `iked-addke-watch` cron reports the first one automatically.

## Begin — RFC 9242 IKE_INTERMEDIATE, then RFC 8784 PPK

Order decided 2026-09-18 (supersedes the old "8784 first", which predates 9370):
**9242 before 8784** — 9242 is the init-time PQC carrier that pairs with the
landed ML-KEM and iOS implements it (live-testable against the phone), whereas
8784 PPK needs a PSK-provisioning story first.

- **RFC 9242 (IKE_INTERMEDIATE, exch 43):** split after IKE_SA_INIT and before
  IKE_AUTH; one or more rounds, each carrying a NONCE (type 40); each round's
  secret feeds SKEYSEED so a store-now-decrypt-later attacker can't start on the
  DH until all rounds complete. Entry: new exchange-type dispatch in
  `iked/ikev2_established_recv` (as ADDKE's IKE_FOLLOWUP_KE), responder + initiator,
  new `iked/ikev2_intermediate.c`, gate `--enable-intermediate` (auto, empty TU
  off-path), SKEYSEED feed near `ikev2_prf_plus` / `compute_keymat`.
- **RFC 8784 (PPK):** PPK_ID notify + quantum-resistant pre-shared mixing into
  SK_PRF/SKEYSEED + sequential counter to prevent reuse. New PPK config +
  notify handling + key feed; needs a PSK source. After 9242.

## Still this chunk (do not start EAP/8784)

1. iOS-initiated CHILD rekey (~1440s) with the shared PFS gate. The
   20:01:34 attempt was the first ever to complete the exchange (no
   `ts unacceptable`, no SEGV, old child deleted per §2.8) — iOS
   still deleted the IKE_SA one message later; the PFS gate is the
   fix candidate.  Unproven until a session with floor=0 lives that
   long.
2. One 3600s hard cycle, same pid, ESP still moving.
3. Host reboot with a live dump. `bind 4500 already in use` on restart.

## Later

- IKEv2 EAP-MSCHAPv2 + RADIUS.
- QCD token-taker. RFC 8784 PPK — **now ordered after RFC 9242** (see Begin section above); needs a PSK source.
- Transport-mode IKEv2 e2e; IPv6-in-IPv4; Windows/Android/macOS.
- Fuzz `ikev2_input` / `isakmp`. Live IKEv1 NAT-OA peer.

## Do not

- Bounce live iked with a phone session unless asked.
- Call host reboot or RFC 5723 "resume" until measured.
- xxd resume dumps past magic/cookies.
- Ping the CP inner from WSL.
- Push anywhere but `mine`.
- Run linux-matrix IKE rows (workers=0) against a live phone session.
