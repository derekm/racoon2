# EAP initiator role — design note & validation

Status: **Not implemented — responder EAP only; design sketch for a future
initiator role.**  This file exists to record *what an initiator-side EAP
(client) role would have to do*, and to state plainly that none of it exists
today.  Nothing in this note is a claim that the feature works; the "Responder
EAP (implemented)" section is grounded in code, the "Initiator EAP" section is
design intent only.

Branch: `int/gsoc2026` (this is a design/status note, not a commit pin — check
`git log` for the current HEAD).  Companion doc: `doc/eap-design.md`
(responder-side EAP + RADIUS, *implemented*).

## What this is

A half-B design note covering the **initiator role of EAP in IKEv2 IKE_AUTH**
(RFC 7296 §2.16 from the initiator's side): racoon2 acting as an **EAP client**
that runs an EAP method against a remote IKEv2 responder acting as an EAP
server, then derives the IKEv2 AUTH on the initiator from the resulting MSK.

It also double-checks the implemented reality: today racoon2 implements EAP
**only as an IKEv2 responder**, relaying EAP to an external FreeRADIUS server
and deriving the MSK for a peer's AUTH.  There is **no initiator-role EAP** in
the tree.  Confirmed by inspection of `iked/` (see "Validation" below).

## Scope

- **In scope (this note):** accurate description of the implemented responder
  EAP; a design sketch for the not-yet-built initiator (EAP client) role;
  risks and open items.
- **Out of scope:** implementing the initiator role.  This is a design note
  only, matching the "design note & validation" convention of `eap-design.md`.

## Responder EAP (implemented)

racoon2's IKEv2 side performs EAP **only as a responder** (RFC 7296 §2.16
server window): an external initiator omits AUTH from its first IKE_AUTH, and
racoon2 relays EAP-Request/Response to an external FreeRADIUS server, then
derives a shared key (the MSK) used to build and verify the IKEv2 AUTH.  Key
code locations (`iked/`):

- **EAP entry (initiator sends IDi with no AUTH):** `iked/ikev2_sa_auth.c`
  around `responder_ike_sa_auth_eap_*`.  The no-AUTH-with-IDi case is detected
  at `ikev2_sa_auth.c:852-858` (`id_i && !auth && ikev2_eap_remote()`), the SA
  is parked in `IKEV2_STATE_RES_IKE_AUTH_EAP` at `ikev2_sa_auth.c:995`, and an
  EAP-Identity Request is emitted (`ikev2_eap_relay_start`, `iked/ikev2_eap_relay.c:26-35`).
- **Responder relay state machine:** `iked/ikev2_eap_relay.c`
  (`ikev2_eap_relay_start` / `ikev2_eap_relay_consume`, contract in
  `iked/ikev2_eap_relay.h`); continuation/resume handlers
  `responder_ike_sa_auth_eap_recv` / `_cont` / `_resume` at
  `iked/ikev2_sa_auth.c:1122 / 1175 / 1421`, and the final
  `responder_ike_sa_auth_eap_final_recv` at `iked/ikev2_sa_auth.c:1557`.
- **States:** `IKEV2_STATE_RES_IKE_AUTH_EAP` (=9) and
  `IKEV2_STATE_RES_IKE_AUTH_EAP_FINAL` (=11) in `iked/ikev2_impl.h:116,120`.
- **MSK storage:** on `ike_sa->eap_msk` (`iked/ikev2_impl.h`, freed at
  `iked/ike_sa.c:1328-1329`); Acceptance stores it and sends EAP-Success at
  `iked/ikev2_sa_auth.c:1468-1477`; the MSK must be exactly 64 octets
  (`iked/ikev2_sa_auth.c:1238,1595` and `iked/ikev2_auth.c:181-188`).
- **MSK → AUTH on the responder:** the MSK substitutes for the pre-shared key:
  `ikev2_auth_shared_secret()` picks `sa->eap_msk` over the PSK at
  `iked/ikev2_auth.c:172-191`; the final AUTH verify uses it at
  `iked/ikev2_sa_auth.c:1595-1611`.
- **Config surface:** `kmp_auth_method eap` in the `ikev2` remote section,
  validated at `iked/ike_conf.c:6260-6311` (requires `radius_server` +
  `radius_secret_file`; may pair with at most one signature method; `eap + psk`
  is rejected).  RFC 4739 multi-round responder EAP as the second round is
  described in `doc/config-usage.txt:913-956`.

Note: the auth-method list enum in `doc/config-usage.txt:301-309` does **not**
list `eap` alongside `psk/dss/rsasig/...`, even though `kmp_auth_method eap` is
accepted and validated by `ike_conf.c`.  A doc gap, not a feature gap.

## Initiator EAP (design, not implemented)

This section is **design intent**, not implemented reality.  It outlines what an
initiator-role EAP client would need, mirroring the responder's MSK handling.

### Why the initiator would act as an EAP client

RFC 7296 §2.16 describes EAP inside IKE_AUTH as a way for the **initiator** to
authenticate itself (the responder authenticates with its own method — usually
a certificate).  An initiator that has no shared PSK and no certificate
material acceptable to the responder uses an **EAP method** as its
authentication proof.  In IKE_AUTH the initiator offers EAP by sending `HDR, SK
{IDi, [CERTREQ,] [IDr,] SAi2, TSi, TSr}` (its first IKE_AUTH request, message
3) **without an AUTH payload**; the responder replies with `IDr, [CERT,] AUTH,
EAP`, and the EAP conversation continues as a series of `EAP`/`AUTH` exchanges
until EAP-Success/Failure.  In this role racoon2 is the **EAP peer/client**: it
answers the responder's EAP-Request messages and terminates the EAP method.

### Design sketch for an initiator role

- **EAP method backend.**  Where the responder relays EAP to FreeRADIUS, the
  initiator runs an EAP method locally.  Two options: (a) an **out-of-process
  client backend** (an external EAP supplicant / a method library) that racoon2
  drives per-round — analogous to how the responder drives the RADIUS worker
  pool; or (b) a small **in-process EAP method** for the specific methods
  racoon2 needs to support.  As with the responder (which is method-agnostic
  about MSCHAPv2/EAP-TLS/...), the initiator should treat the method as a
  pluggable component yielding two things: the final MSK and (for mutual
  methods) the master session key / method-finish state the IKEv2 AUTH depends
  on.  The operator would configure which EAP method and identity the initiator
  runs per remote.
- **EAP-Identity first.**  Per RFC 3748 §5.1 and RFC 7296 §2.16, the initiator's
  first IKE_AUTH (no AUTH) precedes the actual EAP method; the responder opens
  with an EAP-Identity Request, which the initiator answers with its configured
  EAP identity (the responder's `ikev2_eap_identity_string()` shows the wire
  shape, `iked/ikev2_eap.c:247`).  A design would reuse the existing
  EAP payload emit/parse helpers (`iked/ikev2_eap.c`, `ikev2_eap_emit.c`) but
  drive them from the client side.
- **MSK → AUTH, mirrored from the responder.**  The crucial symmetric step: the
  responder derives a 64-octet MSK from the EAP method and feeds it to
  `ikev2_auth_shared_secret()` (`iked/ikev2_auth.c:172-191`) so the MSK
  substitutes for the PSK in `prf(MSK, ...)` over the **InitiatorSignedOctets**
  (this is the initiator's AUTH).  An initiator role must **derive the same MSK
  from the same EAP method** (RFC 5216 §2.3 EAP-TLS / RFC 3079 §3.3 MSCHAPv2
  shapes — the responder documents this at `iked/ikev2_auth.c:175-188`), store
  it on the SA exactly like `ike_sa->eap_msk`, and then compute and verify the
  MSK-based AUTH.  Because MSK derivation is the single point of agreement
  between the two sides, the initiator's derivation must be byte-identical to
  the responder's — this is where the design inherits the responder's 64-octet
  fail-closed check.
- **IKEv2 message flow.**  A new initiator state (e.g. an
  `IKEV2_STATE_INI_IKE_AUTH_EAP` analogous to the responder's state 9/11) would
  own the repeated `IKE_AUTH` exchanges carrying EAP payloads, advance the
  message id per round (the responder does this at `iked/ikev2_sa_auth.c:1005-1008`),
  and finish by sending the initiator AUTH once the MSK is known.  This mirrors
  `responder_ike_sa_auth_eap_cont` / `_resume` / `_final_recv`, but on the
  initiator side of the exchange.

### Implemented initiator-side EAP: none

There is **no initiator-role EAP** in the tree — no initiator EAP state, no
client EAP method, no MSK-derived AUTH emitted as an initiator.  Validation:

- No `IKEV2_STATE_INI_*_EAP` state exists; the only initiator IKE_AUTH states
  are `IKEV2_STATE_INI_IKE_AUTH_SENT` / `_RCVD` (`iked/ikev2_impl.h:110,112`).
  The only EAP states are the responder's `RES_IKE_AUTH_EAP` (+`_FINAL`).
- The single function that looks initiator-side, `initiator_state1_send_eap()`
  (`iked/ikev2_sa_auth.c:3438`), is an **empty commented-out stub inside
  `#ifdef notyet ... #endif`** (`iked/ikev2_sa_auth.c:3434-3471`, a quoted
  RFC 7296 §2.16 trace).  It is dead code, not a feature.
- All EAP code paths in `iked/` (relay, drive, round, emit, RADIUS worker) are
  responder-facing; the "client-style" EAP code that exists is confined to
  hermetic tests that *emulate a client* to exercise the responder
  (`eapdrivetest.c`, `relayworkertest.c`, `eaproundtest.c`, `radiuslive.c`).

## Risks / open items

- **MSK agreement is the hard part.**  The initiator and responder must derive
  the exact same 64-octet MSK or the MSK-based AUTH fails closed.  Any
  out-of-process client backend must hand back the same key the responder's
  RADIUS server computes for the same method — tie the initiator's derivation
  to the responder's (`iked/ikev2_auth.c:175-188`) and to an interop matrix row
  mirroring the `i2ieap-mschapv2` established-state test used for the responder.
- **Method coverage.**  The responder is method-agnostic (RADIUS does the work);
  the initiator must actually *run* a method.  Supporting MSCHAPv2 (password /
  challenge) is the obvious first target; EAP-TLS needs certificate handling on
  the client side.  Decide in-process vs. out-of-process backend before
  implementation; an out-of-process supplicant is lower-risk than writing EAP-TLS.
- **Config surface is responder-only today.**  `kmp_auth_method eap` is
  validated as *responder* relay config (`iked/ike_conf.c:6260-6311`) and always
  requires `radius_server`/`radius_secret_file`.  An initiator config would
  reject/ignore those and instead carry `eap_method` + `eap_identity`, likely as
  a distinct `eap` variant so the same remote section cannot be both a relay
  responder and a client.
- **RFC 5998 / EAP-only and non-mutual methods.**  The responder deliberately
  declined to honour `EAP_ONLY_AUTHENTICATION` for a configured signature method
  (see `doc/eap-design.md`); the initiator design should make sure the responder
  still authenticates itself (cert) for non-mutual methods like MSCHAPv2, and
  decide how an initiator handles a responder that offers EAP-only.
- **Message-id / retransmit window.**  The initiator sends each EAP round as a
  fresh request needing its own message id and retransmit handling — mirror the
  responder's advance-at-`iked/ikev2_sa_auth.c:1005-1008` to keep the window
  correct over the multi-round exchange.
- **Doc gap:** `doc/config-usage.txt:301-309` omits `eap` from the
  `kmp_auth_method` algorithm list while `ike_conf.c` accepts it — fix when the
  initiator config is added.

## Validation

- Responder EAP present and reachable in source (see "Responder EAP
  (implemented)" for file:line).
- `iked/` has no `IKEV2_STATE_INI_*_EAP`; the lone initiator-looking EAP
  function is a commented `#ifdef notyet` stub at
  `iked/ikev2_sa_auth.c:3434-3471`.
- Consolidated from a full read of `doc/eap-design.md`, the responder EAP state
  machine in `iked/ikev2_sa_auth.c`, `iked/ikev2_eap_relay.c`, `iked/ikev2_auth.c`,
  and the config validation in `iked/ike_conf.c` / `doc/config-usage.txt`.
