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
- Restart the service after install: `systemctl restart iked` (unit is `iked.service`, not `racoon2-iked`).
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
  IKE_FOLLOWUP_KE → deferred child install) and **initiator** child ADDKE;
  reverse-pass proposal skip; resume skips incomplete-keymat children;
  teardown zeroizes keymat. Config `esp_addke_alg { mlkem768; };`,
  `--enable-addke` (OpenSSL ≥3.5), live on Fedora (NRestarts=0).
- **Responder IKE_SA-rekey ADDKE feed — KEr-ct bug fixed (`0bc1149`);
  initiator feed implemented (`8a49dbf`).** The responder answers the
  IKE_FOLLOWUP_KE with the freshly-encapsulated **ciphertext** (RFC 9370
  s2.2.4), not the shared secret.  The initiator can now offer type-6 on its
  IKE_SA-rekey (addke_unrequested), keygen, send the followup request, and
  complete SK(1).  Build + `make check` green (addketest/addkekat, FAIL 0);
  child-rekey ADDKE regression green.  **IKE_SA-rekey ADDKE is end-to-end
  matrix-proven** as `i2ikesa-addke` (both sides log the same SK(1) SKEYSEED
  after the followup; see below).
- Independent pin: `addkekat` replays NIST FIPS 203 KATs — **20/20** shipped,
  **1000/1000** full file, suite **7/7**; log in `doc/kattest-results.txt`.
- Full write-up: `doc/addke-design.md` (inventory, gaps, decision criteria).

**Child-rekey ADDKE — proven 2026-09-19 (netns i2i matrix).** The CREATE_CHILD
rekey re-offers type-6 (initiator + responder), the responder marks the rekey
child pending (`peer_type6=1`) and `ikev2_create_child_responder_cont` defers
the install + arms the 10s wait; the IKE_FOLLOWUP_KE exchange then completes
and **both** sides install the rekey child with ML-KEM-derived keymat
(`addke_sk` = SK(1), 32 B, appended to KEYMAT after Nr per rfc9370 s2.2.4) —
new SPI takes packets, `REKEY_SOAK_RESULT=0`.  Net fix: `ikev2_createchild_
initiator_recv` no longer finalizes the rekey (deleting the old child / logging
"rekey complete") while the ADDKE child is still `addke_pending`; the old-child
delete is deferred to `ikev2_initiator_followup_complete` once the KEM child is
installed.  **Initiator IKE_SA-rekey ADDKE** is matrix-rowed as
`i2ikesa-addke` (both sides log the same ADDKE SKEYSEED after
IKE_FOLLOWUP_KE).  (Outbound
fragmentation of our IKE_FOLLOWUP_KE was listed here before a 2026-09-18 code
check showed it is already handled by `ikev2_transmit`/`ikev2_transmit_response`
→ `ikev2_frag_send` when RFC 7383 is negotiated; not a gap.)

**IKE_AUTH initial-child ADDKE false positive — fixed 2026-09-18 (f3ad6e0).**
The initial "CHILD UP" from the isolated ring was a plain ESP install: with
`esp_addke_alg` on the sa, `ikev2_construct_sa` offered type-6 on the IKE_AUTH
child too, `ikev2_proposal_to_ipsec` skipped it with `unexpected transform
type (6)`, and the armed IKE_FOLLOWUP_KE could never complete → a 10s timeout
aborted the child.  Fix: `ikev2_ipsec_sa_to_proplist` emits type-6 only when
the parent IKE_SA is ESTABLISHED (CREATE_CHILD / rekey), so the initial child
is plain and stable.  This is the documented design ("IKE_AUTH still has no
type-6"); the false-positive "CHILD UP" proof was withdrawn.

## Begin — RFC 9242 IKE_INTERMEDIATE, then RFC 8784 PPK

**Priority change 2026-09-18 (iPhone cannot hold a session to the ~1440s rekey —
two consecutive err=110 DPD-timeout deaths: 06:39→07:02, 07:04→07:19, no DELETE,
no CREATE_CHILD. So phone-driven PQC rekey validation self-blocks; the Linux
matrix now carries the PQC e2e proof, and the iPhone is only the final interop
check.)**

Order of execution decided 2026-09-18 (supersedes the old "8784 first", which predates 9370):
**9242 before 8784** — 9242 is the init-time PQC carrier that pairs with the
landed ML-KEM and iOS implements it (live-testable against the phone), whereas
8784 PPK needs a PSK-provisioning story first.

- **Matrix-first PQC e2e, then 9242 rows, then iPhone:**
  1. Standing up the matrix under **WSL NAT** — `.wslconfig` switched back to
     `networkingMode=nat` on 2026-09-18 (mirrored left eth0 DOWN and broke the
     netns matrix). WSL verified: root netns ok, strongSwan charon U5.9.13
     (ML-KEM-capable) present, r2 build tree at `/home/derek/src/racoon2`.
  2. Fedora must be able to run the matrix: it has `~/src/racoon2` but **no
     strongSwan/charon** — install it, or add iked↔iked (charonless) rows.
  3. Add matrix rows: `ikev2-netns-addke` (charon mlkem768 vs racoon2
     `esp_addke_alg` responder, child-rekey ADDKE e2e), then `ikev2-netns-int`
     (`i2iinit-addke` landed 2026-09-19 once 9242 landed).
- **ADDKE matrix peer decision (2026-09-18): iked↔iked, not charon.** Every
  available strongSwan lacks ML-KEM: WSL Ubuntu charon 5.9.13 (no ML-KEM), and
  Fedora RPM strongSwan 6.0.7 (`/usr/libexec/strongswan/charon` has zero
  `mlkem768` strings — built on OpenSSL 3.5.8 but the spec didn't enable it).
  Neither can offer type-6 ADDKE. So the `ikev2-netns-addke` peer is a second
  racoon2 WITH_ADDKE: **racoon2-as-initiator (offers type-6 on child / IKE_SA)
  ↔ racoon2-with-ADDKE responder** in two netns on Fedora (host ns + one netns,
  or two netns). Self-contained; verifies the exact initiator-ADDKE code we
  need continuously. Requires a new iked↔iked 2-namespace harness (the current
  kinds/ikev2.sh is charon-centric). Fedora strongSwan 6.0.7 RPM stays useful
  for the non-PQC rows; 9242/IKE_INTERMEDIATE has the same peer problem — an
  iked↔iked `ikev2-netns-int` row reuses the harness once 9242 lands.
- **iked↔iked harness live (2026-09-18): `samples/linux-matrix/i2i/`.** Three
  real racoon2-as-initiator-in-netns bugs found & fixed (never exercised
  before): multi-instance admin-socket collision (`RACOON2_ADMIN_SOCK` env),
  the `sadb_poll` uninitialized-`rcpfk_msg` SEGV (memset), and the
  acquire-initiated child GETSPI using the acquire's seq-0
  (mint `sadb_new_seq()`).  Plus `ikev2_frag_send` used a RECEIVE-direction
  key to re-extract its own message's inner (garbage fragments →
  `ikev2_decrypt_local`, key-direction fix `00d671d`) and the ADDKE link
  mismatch (`followup_ke_find_child`, `ee81c53`).  Baseline: initial IKE_AUTH
  child now PLAIN + stable (type-6 gated to ESTABLISHED); the ML-KEM rekey
  is matrix-proven (`i2ike-addke` / `i2ikesa-addke`, see above).  iPhone stays
  last until the router DNAT points at this box.
- **RFC 9242 (IKE_INTERMEDIATE, exch 43):** negotiated by the
  `INTERMEDIATE_EXCHANGE_SUPPORTED` notify (16438) in IKE_SA_INIT; IKE_INTERMEDIATE
  exchanges run sequentially between IKE_SA_INIT and IKE_AUTH (msgid 1,2,…), each
  carrying an Encrypted payload. It is a **carrier** for additional key exchange
  (e.g. ADDKE/ML-KEM) that updates SK_e/SK_a per the applying spec; the rounds are
  bound into AUTH via the **chained IntAuth PRF** (`IntAuth_i/rN`) + `IKE_AUTH_MID`
  chunk appended to each peer's signed/mac'd blob.  **Landed in `iked/ikev2.c`;**
  the minimal `iked/ikev2_intermediate.c` TU holds only
  `ikev2_intermediate_clear` (SA-dispose release of IntAuth/ML-KEM state) — the
  exchanger itself is still the ~7.8k-line tail of `ikev2.c`.  Initiator
  offers N(16438) when
  `WITH_INTERMEDIATE` is on; responder echoes it only when the peer offered it
  **AND** the selected proposal carries type-6 (`negotiated_sa->addke != 0`)
  **AND** the negotiated IKE cipher is AEAD (IntAuth_A is deterministic only
  for AEAD).  On the initial IKE_SA, a peer type-6 WITHOUT 16438 is skipped
  (RFC 9370 s2.2.1 — never select-and-strip), and the selected ADDKE method
  is read from the **matched** peer proposal only (never a non-selected one).
  IntAuth for a round is chained with the **PRE-update** `sk_p` (RFC 9242
  s3.3.2), i.e. before `ikev2_intermediate_update_keys`, which swaps
  SKEYSEED generations all-or-nothing (fail-closed).  AUTH fails closed if the
  IntAuth appendix cannot be built.  IntAuth_A reconstruction uses the
  adjusted length fields (Enc generic = `4 + |P|`, IKE Length = `28 + enc`).
  Matrix proof is `i2iinit-addke` (Fedora / OpenSSL ≥ 3.5).  iOS sending
  16438 is still the live interop target.  IKE_INTERMEDIATE runs BEFORE
  IKE_AUTH (RFC 9242 s3.2) — it is not `ikev2_established_recv`.  Gate
  `--enable-intermediate` in `iked/configure.ac` (auto-follows `--enable-addke`).
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

## Roadmap adoption (original README "features to support")

- **English documentation — adopted + audited (closed out).** The doc corpus
  is bilingual (every `.ja.txt` has an EN twin: config-usage, iked-memo,
  kinkd-impl/install, libracoon, specification, system-message) plus EN
  README/INSTALL/USAGE and our `addke-design.md` / `int-gsoc2026.md`.
  `config-usage.txt` documents `addke_required`/`addke_unrequested`.
- **Easy configuration tool — adopted (goal), spec only, not yet in tree.**
  Spec at `doc/config-tool.md`.  The pending deliverable is
  `samples/racoon2-schema.json` (JSON Schema payload) +
  `utils/racoon2-config.py` (validate/generate), gated by the real parser
  (`iked -F -f generated.conf` → no `syntax error`).  Schema derived from
  `cfparse.y`/`cftoken.l`, not hand-maintained.  **Neither file exists yet.**
- **MIPL / SHISA — superseded by existing MOBIKE (RFC 4555).** Legacy
  kernel-Level MIPv6 (mobile IPv6 binding / HA forwarding) never stabilized
  in modern kernels. The modern IKE-level analog — network mobility without a
  home agent — is MOBIKE, which iked **already implements**
  (`ikev2_mobike_apply`, `mobike_supported`, MOBIKE_SUPPORTED notify) and
  which iOS uses; no kernel-MIPv6 work needed.
- **Previous-Racoon config converter — superseded by the easy config tool**
  (generator replaces the syntax-shift converter).

These are orthogonal to the PQC RFC sequence (ADDKE → 9242 → 8784): they are
maintainability/onboarding items that do not block or reorder the crypto
workstream and never conflict with the "Do not" list.

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
