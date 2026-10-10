# Responder-side IKEv2 EAP + RADIUS — design note & validation

Status: **implemented (2026-10-10); responder role only; RADIUS-only backend**
Branch: `int/gsoc2026` (this file is a design/status note, not a commit pin —
check `git log` for the current HEAD).

## Scope

Racoons2's IKEv2 side implements the **responder** role of EAP in IKE_AUTH
(RFC 7296 §2.16): a road-warrior initiator authenticates through an **external
FreeRADIUS server**, and racoon2 relays EAP-Request/Response (RFC 3748
framing) and derives the MSK for the IKEv2 AUTH.  There is **no initiator-role
EAP** (racoon2 never acts as an EAP client) and **no in-process EAP method
suites** — MSCHAPv2, EAP-TLS and friends are all performed by the RADIUS
server; racoon2 is method-agnostic about anything between Identity and
Success/Failure.

## What is implemented (source of truth: code + `make check`)

- Dedicated responder state machine `IKEV2_STATE_RES_IKE_AUTH_EAP` (+ final)
  with multi-round continuation, parking/resume, and event handling for every
  EAP payload the initiator can send.
- Strict EAP-Response validation: payload Length bounds, EAP **Identifier**
  echo (must match the last Request), and EAP-Success treated as exactly the
  4-byte EAP-Success (RFC 7296 forbids it carrying data); Success re-emits
  its 4 bytes on retransmit.  A rejected EAP-Response is answered with
  **EAP-Failure before the IKE SA aborts** (never a bare abort).
- RADIUS relay (`radius_server` + `radius_secret_file`) with multi-round
  Access-Request / Access-Challenge / Accept.  IPv4 address parsing;
  IPv6 RADIUS servers are not yet supported.  Secrets are read from a file,
  never placed on a command line, and never logged.
- MSK derivation (RFC 5216 §2.3 EAP-TLS shape / RFC 3079 §3.3 MSCHAPv2:
  Recv(16)‖Send(16)‖zeros; fail-closed if the MSK is not exactly 64 octets)
  and the RFC 5998/7296 §2.15 AUTH built from that MSK (prf(MSK, ...) over
  SignedOctets) — the same MAC shape as the PSK path.
- **RFC 5998 EAP_ONLY_AUTHENTICATION policy (deliberately conservative):**
  the notify is *recorded*, but the responder does **not** honour it by
  omitting CERT+AUTH when a signature method is configured.  Non-mutual EAP
  methods (e.g. MSCHAPv2) still require the responder to authenticate itself
  with its certificate; silently dropping CERT+AUTH on a client's notify
  would let a single-slot IKE_AUTH carry no responder authentication at all.
  EAP-only final is emitted only when no signature method is actually
  configured.  This is a policy choice, not an RFC violation — RFC 5998 §3
  makes honoring the notify optional.
- Responder certificate + signature AUTH alongside EAP (or the pure EAP-only
  path), with the ECDSA method selected from the certificate curve
  (P-256/384/521), not hardcoded.  Fail-closed: if a signature method is
  configured but the CERT/key cannot be resolved, the exchange aborts rather
  than silently degrading to EAP-only.
- Retained child-offer payloads (`eap_sa_i2`, `eap_ts_i`, `eap_ts_r`) owned
  and freed on dispose/abort so the final AUTH-only message can still create
  the Child SA.
- Config: `peers_id` enforced on the EAP entry path; `radius_server` /
  `radius_secret_file` per remote.  A missing/empty RADIUS config fails
  closed at exchange time.

## Tests

- Hermetic `eapmethodtest` (in `make check`): responder AUTH-method
  selection, NULL-safety, ECDSA curve→method mapping, key-load-failure → 0,
  EAP-only selection, RSA + SIG_HASH.
- MSK-shape and fail-closed coverage (32/64-octet MPPE lengths, wrong-length
  reject).
- Box-gated matrix row `i2ieap-mschapv2` (kind `i2ieap`): charon initiator,
  MSCHAPv2 over FreeRADIUS, reaches IKE_SA/CHILD **ESTABLISHED** with
  `MSK stored (l=64)` + responder CERT auth.  `gate=box` because it needs
  charon + a RADIUS server.

## Known limits

- RADIUS-only backend: no in-process EAP-TLS/PEAP/TTLS/EAP-FAST.
- Initiator-role EAP not implemented (responder server scope).
- IPv6 RADIUS servers not parsed.
- Broad interop (real phones / Windows / multiple RADIUS vendors) not yet run.

## RFC 5998 history reconciliation

`d12f5c4` initially honoured `EAP_ONLY_AUTHENTICATION` by omitting CERT+AUTH.
`2a4adf6` / `c47a01b` reversed that to the current recorded-only behaviour
for a configured signature method.  The final state is the safer one; the
`eap_only` field name now reflects logging-only use.  This note is the
definitive statement of the chosen policy so readers are not confused by the
older commit.
