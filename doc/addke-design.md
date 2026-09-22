# RFC 9370 ADDKE / ML-KEM (PQC) in racoon2 — design note & validation

Status: **implemented & config-gated; matrix-proven on the Fedora box**
Branch: `int/gsoc2026` (this file is a design/status note, not a commit pin —
check `git log` for the current HEAD of the implemented code).

## What this is

IKEv2 Additional Key Exchange (RFC 9370, transform type 6 ADDKE1) with
ML-KEM-768 (IANA KE/ADDKE type 4 id 36) as the post-quantum component,
integrated into the racoon2 responder so the **iPhone's child-rekey** offering
of type-6 is answered correctly instead of with an RFC 9370-invalid strip.
ADDKE is optional (RFC 9370 §1.3): it carries on IKE_FOLLOWUP_KE exchanges after
CREATE_CHILD_SA, one round per method, linked by the `ADDITIONAL_KEY_EXCHANGE`
(16441) notify, before the child keymat is computed.

The whole thing is gated on `--enable-addke` (default auto), which probes
`<openssl/ml_kem.h>` (OpenSSL ≥ 3.5). OpenSSL 3.0 / distros without the header
compile an empty TU and the non-ADDKE behaviour is unchanged.

## Implementation inventory (source of truth: code + `make check`)

Done and verified (Fedora 44, OpenSSL 3.5, `WITH_ADDKE`):

- Config keyword `esp_addke_alg { mlkem768; };` (and `ah_addke_alg`) through the
  full ENCR/INTEG/DH chain: `rc_type` – lexer – grammar – `cfsetup` –
  `SA_CONF(addke_alg)` – `ikev2_transf_addke[]`. Shipped in
  `doc/config-usage.{txt,ja.txt}` in the same commit.
- **Responder** child rekey with ADDKE: MINE carries type-6 → selected → echoed on
  the accepted peer proposal (with the peer's `p_no` stamped, not our config
  index) → 16441 → `IKE_FOLLOWUP_KE` → KEr decap → deferred child install with
  the ADDKE keymat. Both the sync and DH-async resume paths mark the child
  ADDKE-pending.
- **Initiator** child ADDKE (racoon2 as initiator offering/accepting type-6 on a
  CREATE_CHILD response): keygen, stash priv + link, send FOLLOWUP_KE with
  `ikev2_request_id`, decap KEr(1), `ikev2_child_addke_install`.
- **IKE-SA-rekey responder ADDKE feed** (item 1 of the roadmap): different
  SKEYSEED `prf(SK_d, SK(0)|Ni|Nr|SK(1)…)`; type-6 treated as optional in the
  IKE-rekey reverse pass; deferral + dedicated timer + adopt from the followup
  handler. (Default iOS IKE_SA rekey offers NO type-6 — correct to not hunt it.)
- **Reverse-pass proposal skip**: in `ikev2_compare_transforms` (what
  `isakmp_find_match` calls) and `ikev2_match_transforms`, every peer transform
  type must exist in ours; peer ADDKE-bearing props fail when MINE has no type-6
  (list-pointer reset before the reverse pass), so a plain peer lands on a later
  non-ADDKE proposal instead of getting a stripped invalid answer.
- **Resume** (`ikev2_resume.c`): a pending-ADDKE child (incomplete keymat, SK(1)
  not yet in GSKM) is skipped on restore; record version bumped; `addke_link_len`
  validated.
- **Teardown hygiene**: `addke_sk`/`addke_link` are `rc_vfreez`-zeroized (they are
  key material); `EVP_PKEY_free` on `addke_priv` guarded `#ifdef WITH_ADDKE`;
  parked IKE-rekey ctx abandoned through the same release path as the wait
  timeout.
- **Unit tests**: `addketest` (algorithm selection, responder followup,
  sequential ADDKE, implicit-rejection, teardown) and `addkekat` (below).

Not implemented (honest list — do not claim these):

- **Outbound** fragmentation of our own IKE_FOLLOWUP_KE is **NOT a gap**: the
  followup is sent through `ikev2_transmit`/`ikev2_transmit_response`, which
  already call `ikev2_frag_send` on any packet ≥576 B (IPv4) / 1280 B (IPv6)
  when RFC 7383 fragmentation is negotiated (`ike_sa->frag_supported`, set on
  the FRAGMENTATION_SUPPORTED (16430) notify).  A fragmented followup over a
  small MTU is already handled.  Removed as a gap on 2026-09-18 after code check.
- **IKE_INTERMEDIATE** (RFC 9242) and INIT-time PQC carry the single pre-AUTH
  ML-KEM round on the initial IKE_SA (exch 43 + N(16438)); matrix row
  `i2iinit-addke` proves the same intermediate SKEYSEED on both sides.
  One round only — ADDKE rounds 2+ are not implemented.
- **IKE_SA-rekey ADDKE on both roles** — matrix row `i2ikesa-addke` proves
  racoon2-as-initiator driving an IKE_SA rekey that negotiates ADDKE and
  completes SK(1) via IKE_FOLLOWUP_KE.

## Independent test vector pin (roadmap item 7)

`addkekat` replays the official NIST FIPS 203 known-answer vectors from
`post-quantum-cryptography/KAT` (`kat_MLKEM_768.rsp`, first 20 shipped; the
harness streams any file size, so the full 1000-vector file runs exhaustively).
This is the independent pin the OpenSSL-vs-OpenSSL CLI cross-check in
`addketest` cannot provide — it catches a shared provider bug. Checks per
vector:

1. **Deterministic keygen** from seed `d‖z` must reproduce the NIST `pk`.
2. **Decapsulation** of the NIST `ct` with our deterministic keypair ⇒ NIST `ss`.
3. **Implicit rejection**: import the NIST `sk`, decap `ct_n` ⇒ `ss_n`.

Result, reproduced on a fresh `git archive` build on the LIVE OpenSSL 3.5.8:
the full **1000/1000** vectors pass (keygen + decap + implicit-reject) and the
shipped 20-vector sample is **20/20**; iked suite **7/7 PASS**.  Run log with
provenance/repro steps: `doc/kattest-results.txt`.  Harness bugs found & fixed
during this:

- `ct_n`/`ss_n` matched **after** `ct`/`ss` (strncmp prefix) — the implicit-reject
  fields never landed; fixed by longest-prefix-first.
- The read loop guard `nvec < KAT_MAXVEC` quit on the `fgets` right after
  `count=19` (nvec already 20), so the 20th vector's fields never parsed and it
  ran against an all-zero seed — a false "vector 19 keygen PK differs". Fixed to
  `nvec <= KAT_MAXVEC`.

Gate: `addkekat` is built only under the `ADDKE` automake conditional, so the
Ubuntu/WSL `--enable-addke`-off path stays 5/5 with no new TU.

## Live deployment state (production, Fedora 44 box 192.168.68.102)

- **Config**: `esp_addke_alg { mlkem768; };` is in the live
  `/usr/local/racoon2/etc/racoon2/macos_ikev2.conf` (the peer include), all four
  `sa_protocol esp` blocks — i.e. ADDKE is **already enabled permanently**.
  `.pre-addke` backup is the no-type-6 variant.
- **Binary**: `/usr/local/racoon2/sbin/iked` — the prod responder is kept at
  the current committed build (rebuilt from HEAD when deployed; check the
  installed binary mtime/hash, not this file). Built `--with-km-backend=xfrm
  --enable-pcap --enable-addke`; `WITH_ADDKE` confirmed via symbols
  (`ikev2_followup_ke_recv`, `ikev2_child_addke_install`,
  `ikev2_rekey_responder_addke_complete` present).
- **Daemon stability**: iked up since 00:02:34, `NRestarts=0` — the two
  review-round-2 daemon-killers (fragmented-followup message-id assert;
  `get_payload_data_length`-based link length → `STATE_NOT_FOUND`) have not
  recurred.

## Full-cycle validation (roadmap item 8) — remaining gap

The one live event still un-proven is a **completed ADDKE child rekey**
(peer CREATE_CHILD carrying type-6 → our type-6 echo + 16441 + `p_no` stamp →
IKE_FOLLOWUP_KE decap → child keymat install → the NEW SPI shown taking packets
in `ip xfrm state`), on this crash-free daemon. Since the 00:02:34 deploy, three
inbound phone sessions connected and all three aborted `ikev2_abort err=110`
(`:nil` child) — each died at a DPD/initiator timeout **before the ~1440 s child-
rekey boundary**, so no child rekey (ADDKE or otherwise) has fired. The phone
must sustain a session past ~1440 s for the first ADDKE child rekey, then past
~2880 s (IKE_SA rekey, no type-6 on default iOS) and ~4320 s (second child rekey)
for the full child → IKE_SA → child PQC cycle.

Success signature for the soak (all of these on the SAME daemon, NRestarts=0):

- journal TRACE `marked ADDKE pending` then `attached ADDITIONAL_KEY_EXCHANGE`
  on the child-rekey CREATE_CHILD;
- `ikev2_followup_ke_recv` completes (ML-KEM-768 followup is RFC 7383 fragmented;
  the handler sees the REASSEMBLED decrypted KE — a ~340 B journal length is
  expected, not "too small");
- opposite of a `DELETE IKE_SA` a few hundred ms after our rekey answer (that is
  the RFC 9370-invalid-response tell), and no `STATE_NOT_FOUND`/`INVALID_SYNTAX`;
- `ikev2_child_addke_install` / new inbound SPI counter advancing in the JOURNAL +
  `ip xfrm state` after the followup, not just a SADB_ADD/DELETE log.

## Decision criteria for permanent production use

Already satisfied by the live state: WITH_ADDKE binary genuinely in service (not
just built), ~6.5 h NRestarts=0, config parses and runs type-6-enabled every
start. The gate that is genuinely still open is the **live completed ADDKE child
rekey** (above) — until one is observed end-to-end on a crash-free daemon,
"phone-ready" is not established, per the standing bar that a green `make check`
is not a live proof. That single event, plus a clean multi-rekey soak, closes
item 8.

## Roadmap (remaining, not the landed path)

1. **ADDKE rounds 2-7** as config. One ML-KEM round is implemented and
   matrix-proven (`i2iinit-addke`, `i2ikesa-addke`, `i2ike-addke`).
2. **RFC 8784 PPK** mixed into SKEYSEED. Not started.
3. A non-racoon2 ML-KEM peer (strongSwan 6.0+ built with ML-KEM).
4. Fragmented-response loss recovery is now cached in `response_info`
   (not intermediate-only). A 576-MTU kill test that drops a FOLLOWUP
   fragment and gates on the replay is still TODO.

## Dependencies & reproducible proof

- Fedora 44, OpenSSL 3.5.8 (provider backend; `<openssl/ml_kem.h>`,
  `NID_ML_KEM_768`, `OSSL_PKEY_PARAM_ML_KEM_SEED`). Ubuntu 3.0 auto-off — the
  empty-TU path stays green.
- Full suite on the `WITH_ADDKE` box: `make -C iked check` ⇒
  `eaytest / evlooptest / workerstest / resumetest / fragtest / addketest /
  addkekat` = **7/7 PASS, 0 FAIL**. Gate-off (WSL) ⇒ 5/5, `addkekat` unbuilt.
- Cross-check pin: `openssl pkeyutl -encap/-decap` against the provider both
  directions (CLI keygen + our encap/decap and our keygen + CLI -decap), with
  DER-vs-raw key handling — the addketest CLI cross-check plus the NIST KAT pin.
