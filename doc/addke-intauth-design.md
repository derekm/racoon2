# RFC 9370 ADDKE: ML-KEM Type-4 & non-AEAD IntAuth_B — design note & validation

Status: **ML-KEM-768 as an ADDKE round method (transform type 6, IKE KE/ADDKE
type 4, IANA id 36): implemented & config-gated, `make check` green. IntAuth:
the code builds the RFC 9242 §3.3.2 PRF-based method — i.e. the non-AEAD
"method B" (two separate per-direction invocations, chained and concatenated),
NOT AEAD "method A" (single combined tag).** See "IntAuth integrity-auth
method" below for the exact lines that prove B and the honest caveat about the
code's own `IntAuth_A` naming.
Branch: `int/gsoc2026` (this file is a design/status note, not a commit pin).

## What this is

RFC 9370 lets IKEv2 run *multiple* key exchanges and mix PQC with classical DH.
The additional key exchanges are carried either by `IKE_INTERMEDIATE` (RFC 9242
exch 43) on the **initial IKE SA**, or by the new `IKE_FOLLOWUP_KE` (RFC 9370
exch 44) on **CREATE_CHILD_SA / rekey**, one round per method, linked by the
`ADDITIONAL_KEY_EXCHANGE` (16441) notify. Each ADDKE round is negotiated as a
transform of type 6..12 (Additional Key Exchange 1..7) whose Transform ID comes
from the shared Transform-Type-4 / Key-Exchange-Method registry. Round shared
secrets concatenate into `SK(1)||..||SK(n)`, which merges into SKEYSEED (initial
IKE SA) or the child keymat (CREATE_CHILD).

This note covers the two pieces the half-B task centres on, as they actually
land in the tree:

1. **ML-KEM-768 (Type-4 method)** running as an ADDKE round — the
   `ikev2_addke.c` crypto/negotiation engine, common to both the
   IKE_FOLLOWUP_KE child/IKE-rekey path and the IKE_INTERMEDIATE initial path.
2. **INTEGRITY-AUTH (IntAuth)** — how the IKE_INTERMEDIATE rounds are bound
   into the IKE_AUTH AUTH payload so the pre-AUTH PQC exchanges are
   authenticated. The code implements the **non-AEAD PRF method** ("method B"
   in this task's labels), not the single-tag AEAD method ("method A").

The `ikev2_addke.c` design/validation groundwork and its live-deploy and matrix
status live in `doc/addke-design.md`; this note focuses on the ML-KEM Type-4
component and the IntAuth method, at the source level.

## Implementation inventory (source of truth: code + `make check`)

Read from the tree on branch `int/gsoc2026` (paths relative to the repo root):

- **ML-KEM param table** — `iked/ikev2_addke.c:116-124`
  `ikev2_addke_mlkem_params[]`: IKE Type-4/KE-method ids 35=ML-KEM-512,
  36=ML-KEM-768, 37=ML-KEM-1024, mapped to OpenSSL scheme names
  `ML-KEM-512/768/1024`, NIDs (`NID_ML_KEM_768`), and the FIPS 203 octet
  lengths (`OSSL_ML_KEM_768_PUBLIC_KEY_BYTES` = 1184,
  `OSSL_ML_KEM_768_CIPHERTEXT_BYTES` = 1088). Type-4 mapping stated at
  `ikev2_addke.c:103-107` (ids 35/36/37 per `draft-ietf-ipsecme-ikev2-mlkem-09`).
- **Crypto via OpenSSL EVP** — `ikev2_addke.c`:
  keygen 253-294 (`EVP_PKEY_CTX_new_from_name(...,"ML-KEM-768",...)` +
  `EVP_PKEY_keygen` + `EVP_PKEY_get_raw_public_key`);
  encapsulate 300-354 (`EVP_PKEY_new_raw_public_key` → `EVP_PKEY_encapsulate`
  → 1088 B ct + 32 B ss);
  decapsulate 360-392 (`EVP_PKEY_decapsulate`). Shared secrets are kept out of
  logs and zeroized (`OPENSSL_cleanse`, `rc_vfreez`).
- **Wire format** — `KEi` = the raw 1184 B ML-KEM-768 public key in the
  `IKE_FOLLOWUP_KE` KE payload; `KEr` = the 1088 B ciphertext; the KE payload
  method field holds the negotiated transform id 36 (`ikev2_addke.c:457-487`
  round diagram, and the KE-method field set at 583 / 1163 / 1427).
- **Round driving** — responder `IKE_FOLLOWUP_KE` handler
  `ikev2_followup_ke_recv` (`ikev2_addke.c:768-1602`): encap, fresh-link
  management, multi-round accumulation into `child_sa->addke_sk`; initiator
  `ikev2_initiator_followup_send/complete` (567-616 / 649-765). Deferred child
  install via `ikev2_child_addke_install`.
- **ADDKE externs** — `iked/ikev2_impl.h:763-781` (`WITH_ADDKE`): the
  mlkem keygen/encap/decap/round entry points, all gated on
  `#include <openssl/ml_kem.h>` (OpenSSL ≥ 3.5).
- **IntAuth state** — `iked/ikev2_impl.h:296-303` (`WITH_INTERMEDIATE` block):
  `intauth_i` / `intauth_r` (the two PRF chains) plus `intermediate_req` /
  `intermediate_resp` (this round's AUTH-able content), `intermediate_rounds`,
  `intermediate_priv` (ML-KEM keypair).
- **Tests** — `addketest` and `addkekat` (NIST FIPS 203 KAT) cover the ML-KEM
  crypto + followup engine; recorded as `7/7 PASS` (0 FAIL) in
  `doc/addke-design.md` §Dependencies for the WITH_ADDKE Fedora box. This note
  verified the `addkekat` KAT harness paths in `doc/addke-design.md:72-99`.

## ML-KEM Type-4 component

ML-KEM-768 is a Key-Encapsulation Mechanism, so its ADDKE round is asymmetric
one-ring: the **initiator** sends its public key in `KEi` and the **responder**
encapsulates and returns a ciphertext in `KEr` (the shared secret is 32 octets,
FIPS 203). The code contrasts this with a classical DH round, where both sides
send a public value and each computes `g^xy` (`ikev2_addke.c:137-163` method
dispatch, 175-218 round keygen, 1252-1319 responder/initiator branches).

- Type-4/ADDKE id 36 selects the 768 parameter set, `ML-KEM-768` scheme,
  `NID_ML_KEM_768`, 1184 B pub / 1088 B ct / 32 B ss (`ikev2_addke.c:119-120`).
- The ADDKE round keygen keeps the initiator KEM keypair in
  `child_sa->addke_priv` (an `EVP_PKEY`) (`ikev2_addke.c:189`); the same
  keypair is stashed in `sa->intermediate_priv` on the initial-IKE_SA /
  IKE_INTERMEDIATE path (`ikev2_intermediate.c:669`).
- The negotiated ADDKE method is recorded on the child / SA and validated per
  round against the negotiated method list (`ikev2_addke.c:216`, 1398-1408;
  `ikev2_intermediate.c:820-844`).
- OpenSSL EVP provides all KEM math; racoon2 only shuttles raw octets and holds
  an `EVP_PKEY` keypair until the ciphertext arrives, then officially drops it
  (`ikev2_addke.c:663-674`).

## IntAuth integrity-auth method

**What the RFCs define.** The IKE_INTERMEDIATE exchanges happen before IKE_AUTH,
so they are not yet authenticated; RFC 9242 §3.3.2 (which RFC 9370 §2.2.3
incorporates for the initial-IKE_SA ADDKE path) binds them into IKE_AUTH by
appending to the signed/MACed octets:

    IntAuth  = IntAuth_iN | IntAuth_rN | IKE_AUTH_MID
    IntAuth_iN = prf(SK_piN, IntAuth_i(N-1) | IntAuth_iNA [| IntAuth_iNP])
    IntAuth_rN = prf(SK_prN, IntAuth_r(N-1) | IntAuth_rNA [| IntAuth_rNP])

This is a **PRF-based, non-AEAD construction with two separate invocations per
round** — one keyed by `SK_pi` (initiator→responder direction, `IntAuth_i`) and
one by `SK_pr` (responder→initiator, `IntAuth_r`), chained across rounds and
concatenated. RFC 9242 §3.3.2 calls the input chunks `IntAuth_*A` (the IKE
header + Encrypted generic header with adjusted lengths — ".A" for Associated
Data) and `IntAuth_*P` (the inner plaintext payloads). Published RFC 9242
defines *only* this method for AUTH binding (there is no AEAD-single-tag variant
in the RFC; an AEAD IKE cipher is mentioned only because its ICV gives the
in-flight IKE_INTERMEDIATE messages integrity before AUTH exists).

**What the code builds.** The racoon2 source implements exactly this **method B
(non-AEAD, two-invocation)** construction:

- Two independent keyed PRF chains, one per direction — `iked/ikev2_intermediate.c:382-414`
  `ikev2_intermediate_chain_intauth()`: `key = sk_p_i` for dir `i`,
  `key = sk_p_r` for dir `r`; `h = prf(key, prev | content)`;
  `*chain = h`. The chains are the `intauth_i` / `intauth_r` fields
  (`ikev2_impl.h:300-301`).
- Composition of the per-round input (`content` = `IntAuth_A | IntAuth_P`):
  the `.A` chunk (header + Encrypted generic header, adjusted Length fields so
  IV/ICV/pad never leak into the PRF) is built by `intermediate_content_a()`
  (`ikev2_intermediate.c:416-497`); the `.P` chunk (inner plaintext payloads)
  by `intermediate_packet_inner_blob()` (`ikev2_intermediate.c:257-330`); both
  are concatenated for the request (req: `cA | inner`, 723-725) and response
  (resp: `cA | ib`, 896-905), saved as `intermediate_req` / `intermediate_resp`.
- The two directions are chained together into AUTH — `iked/ikev2_auth.c:360-404`:
  appends `IntAuth_i | IntAuth_r | IKE_AUTH_MID` to the blob that is then signed
  (or MACed). `IKE_AUTH_MID` is the IKE_AUTH Message ID as it appears on the
  wire (`intermediate_rounds + 1` for the single-round path).
- The chain is keyed by the **pre-update** `sk_p` generation each round, i.e.
  before `ikev2_intermediate_update_keys()` swaps in the next SKEYSEED
  generation (`ikev2_intermediate.c:569-605`, called before the key update).

**Therefore: the code implements IntAuth method B, not method A.** There is no
single AEAD-tag IntAuth value anywhere: `ikev2_auth.c` concatenates two distinct
`sk_p`-keyed PRF chain values (plus `IKE_AUTH_MID`), which is the signature of
the non-AEAD two-invocation method.

**Honest caveat — the code's own `IntAuth_A` naming.** Several comments and log
strings call the reconstructed input `intermediate_content_a()` "IntAuth_A"
and require an AEAD IKE cipher to run the initial-IKE_SA ADDKE path
(`ikev2_intermediate.c:623-627`; `ikev2.h:109-110`: "IntAuth_A length is exact
for AEAD IKE ciphers; non-AEAD suites skip the intermediate round"). This does
**not** mean the code implements AEAD method A. The `.A` here is the RFC 9242
chunk name (Associated Data: header + Encrypted generic header), and the AEAD
requirement is purely a **transport** precondition: pre-IKE_AUTH,
IKE_INTERMEDIATE messages are only integrity-protected in flight if the IKE SA
encryption algorithm carries an ICV, i.e. is an AEAD. The IntAuth value embedded
in AUTH is, in every case, the two-PRF-chain method B value built above. If a
reviewer reads only the code's "IntAuth_A requires an AEAD" comments and equates
that with "method A", the conclusion would be wrong; the source structure
(`intauth_i`/`intauth_r` split + concatenation) is decisive.

## What is not / gaps

- **AEAD "method A" is not implemented** (no single combined tag as the IntAuth
  value in AUTH) — by design the code follows RFC 9242 §3.3.2's PRF method.
- **`IKE_FOLLOWUP_KE` (child / IKE-rekey ADDKE) does not use IntAuth at all.**
  IntAuth binds only the IKE_INTERMEDIATE rounds of the *initial* IKE SA into
  IKE_AUTH. On the CREATE_CHILD/rekey path the ADDKE `SK(1)||..||SK(n)` feeds
  the child/IKE keymat directly (SK_d / prf+), with no AUTH binding — see the
  deferred-install path `ikev2_child_addke_install` and the SK(1) accumulation
  in `ikev2_addke.c`.
- **Initial-IKE_SA ADDKE requires an AEAD IKE cipher** (`encryptor_icv_length`
  check, `ikev2_intermediate.c:623-627`); non-AEAD suites simply skip the
  intermediate round (`ikev2.h:109-110`). A non-AEAD-capable IntAuth_B path
  would need the PRF method to run without an AEAD transport — not implemented,
  and the PRF method B already interoperates only under an AEAD ICV here.
- **IKE_AUTH_MID reconstruction** assumes the current single-round layout
  (`IKE_AUTH_MID = intermediate_rounds + 1`); a future multi-round / reordered
  msgid allocation must keep it tracking the real AUTH msgid
  (`ikev2_auth.c:371-379`).

## Risks / open items

- **Chunk-name ambiguity risk (documentation)**: `IntAuth_A` as a code label can
  be mistaken for AEAD method A; this note states plainly the implementation is
  method B. If a future change ever does implement AEAD-method-A, the
  `intermediate_content_a` naming and these comments must be revisited so the
  two meanings do not collide.
- **AEAD-only gating** narrows the initial-IKE_SA ADDKE feature to suites whose
  ENCR is an AEAD; adding non-AEAD IKE ciphers would require the PRF method to
  run without relying on an ICV for transport authenticity — an unclimbed hill.
- **Multi-round IKE_INTERMEDIATE** is designed for (per-round method
  dispatch at `ikev2_intermediate.c:632-648, 820-844, 858-891`) but the live
  initial-SA path is single-round (`allow_init_addke`); the IKE_AUTH_MID
  tracking (above) is the brittle spot if it grows.
- **`make check` claim**: crypto/unit coverage (`addketest`, `addkekat`) is as
  recorded in `doc/addke-design.md` (7/7 PASS, WITH_ADDKE). Interop of the
  IntAuth_B AUTH blob against a strict non-racoon2 peer is matrix/box-proven for
  the initial path per that doc, not re-run for this note.
