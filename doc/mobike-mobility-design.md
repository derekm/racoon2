# RFC 4555 MOBIKE mobility — design note & validation

Status: **partial — the roaming-*follower* side is implemented (implicit update on a peer
source change, explicit UPDATE_SA_ADDRESSES accepted, NAT-T mapping follow, responder-follow
COOKIE2 probing); the roaming-*initiator* push side (racoon2 detecting its OWN address change
and actively sending UPDATE_SA_ADDRESSES) is NOT implemented.** racoon2 fills the
remote-access-server / move-accepting role; initiator-originated updates are the design gap.
There is **no `mobike` config knob** in racoon2 — MOBIKE handling is active whenever the peer
advertises MOBIKE_SUPPORTED; the closely related `natt_follow_mapping` knob (default off) gates
only the XFRM_MSG_MAPPING path.
Branch: `int/gsoc2026` (this file is a design/status note, not a commit pin — check `git log`
for the current HEAD of the implemented code).

## What this is

RFC 4555 MOBIKE ("IKEv2 Mobility and Multihoming") decouples an IKE SA's security associations
from a single fixed endpoint pair so that an established SA set can follow a roaming endpoint
without an IKE_SA rekey.  Every mental model of MOBIKE has two roles on the wire, and racoon2
implements them asymmetrically — this note exists to say exactly which half is real.

The code (a dedicated `iked/ikev2_mobike.c`) has one exported *applier*,
`ikev2_mobike_apply(ike_sa, remote, local)`, which migrates the IKE SA and every Child SA to a
new endpoint pair and re-binds the kernel SAD via `SADB_MIGRATE` / `XFRM_MSG_MIGRATE`.  That
function is the heart of the follower (move-accepting) role: it is driven by **observed**
events — the peer's source changing (implicit, RFC 4555 §3.1), an explicit
UPDATE_SA_ADDRESSES request, the kernel's XFRM_MSG_MAPPING NAT-T rebind, or another KM's
XFRM_MSG_MIGRATE — never by racoon2 deciding on its own to move.

The **initiator push role** would be the mirror image: racoon2 notices that *it* has acquired a
new source address (interface came up, its NAT mapping rotated), starts an INFORMATIONAL
exchange carrying N(UPDATE_SA_ADDRESSES), and only commits the endpoint change after the peer
acknowledges.  That code does not exist.  The only genuinely *initiated* mobility in the tree is
the responder-follow probe (below), which is aimed at alternate addresses of the **peer**, not
at publishing racoon2's own.

## Implementation inventory (source of truth: code)

### The applier and the kernel migrate — implemented

`ikev2_move_sa_impl()` (iked/ikev2_mobike.c:206-351) is the single commit function.  Given new
`remote`/`local` it:

1. short-circuits when the endpoints are unchanged (mobike.c:219-222) — so an implicit call
   with no real change is a no-op;
2. rebuilds the Child SAs' selector/`inner`/`lan` endpoint and IPsec mode + reqid from the
   first IPv4 selector and the address-pool lease (mobike.c:237-275); note the **inner
   (traffic) endpoint for the kernel migrate is taken from the CP lease** (`c->lease_list`,
   mobike.c:245-254) when present, not from config;
3. migrates each kernel direction through `ikev2_mobike_migrate_dir()` (mobike.c:77-107) →
   `sadb_migrate(&rc)` (mobike.c:101): OUTBOUND (old_l→old_r ⇒ local→remote), INBOUND
   (old_r→old_l ⇒ remote→local), and for tunnel mode a FWD direction (mobike.c:277-295).  All
   directions must succeed before anything is committed — a partial move leaves a broken SAD
   and a lying endpoint pair (mobike.c:230-236, 287-295);
4. commits in-memory endpoints on every Child SA and on the IKE SA (mobike.c:301-313);
5. migrates the session-resume/ticket-store key **only when `ike_sa->is_initiator`**
   (`ike_msg_resume_store_migrate(old_r, remote)`, mobike.c:316-317): the resume ticket store
   keys on the peer address bytes, so a restored SA must use the new address.  This is the one
   genuinely initiator-role bit of the applier, and it is bookkeeping, not a roam push;
6. re-targets any armed retransmit/response caches to the new addresses so a replay does not
   go to a dead mapping (mobike.c:323-341);
7. re-pins the NAT-D binding report to the new binding (RFC 4555 §3.8, mobike.c:342-344) and
   marks the resume record dirty (mobike.c:347).

For a tcp_encap (RFC 9329 IKE-over-TCP) SA, child ESP must stay UDP-encap **4500/4500**, so a
MOBIKE update must not re-derive `natt_dport` from the TCP stream's peer port —
`ikev2_mobike_natt()` (mobike.c:50-76) pins 4500/4500 for TCP SAs, matching
`ikev2_sadb_natt_tcp_pin` (iked/ikev2_child.c:2509).  For UDP, the derive uses the new endpoints'
ports (mobike.c:67-75).

### Follower (move-accepting) triggers — implemented

- **Implicit update** (RFC 4555 §3.1): `ikev2_established_recv()` (iked/ikev2_informational.c:
  121-131) — for an ESTABLISHED SA with MOBIKE negotiated, any integrity-verified inbound
  message whose **source differs from `ike_sa->remote`** is an implicit address update and
  calls `ikev2_mobike_apply`.  For a tcp_encap SA the compare is **address-only**
  (`rcs_cmpsa_wop`, informational.c:125-127) so the 4500-vs-500 TCP-port difference is not
  misread as a roam, while a genuine peer address change still fires the update.
- **Explicit UPDATE_SA_ADDRESSES**: the notify sets `ike_sa->mobike_update` on the receive
  path (iked/ikev2_notify.c:1140-1145).  It is applied by the INFORMATIONAL responder
  (informational.c:578-581) and by `ikev2_createchild_responder_recv` (iked/ikev2_child.c:
  4502-4505) — the latter covers a peer that rides UPDATE_SA_ADDRESSES inside a CREATE_CHILD_SA
  rekey (iOS does this; see ikev2.c:639-641).  On the create-child path the NAT-D report is
  re-pinned from the current endpoints before replying (ikev2_child.c:4989-5019).
- **NAT-T mapping follow**: the kernel's XFRM_MSG_MAPPING that authenticated ESP-in-UDP now
  arrives from a new source is routed (iked/ike_pfkey.c:702-742) to
  `ikev2_natt_follow_mapping_event()` (mobike.c:136-161), which follows it like an implicit
  MOBIKE update **only when `natt_follow_mapping` is on, the peer is behind NAT, and the SA is
  ESTABLISHED**.  Default is **off** (iked/ike_conf.c:241, 507); there is no `mobike` knob.
- **Follow an external migrate**: `ikev2_kernel_migrated()` (mobike.c:165-171) updates only the
  in-memory endpoints armed caches and NAT-D pins when another KM already issued
  XFRM_MSG_MIGRATE (migrate_kernel == 0).

### Responder-follow probing — implemented (initiated, but toward the *peer*)

When the current path's retransmits are exhausted, `ikev2_mobike_probe_next()` (mobike.c:353-419,
invoked from the timeout machinery at ikev2.c:677-687) mints a fresh COOKIE2 and sends an
INFORMATIONAL with it to the next same-family *alternate* address of the responder
(`extra_addr4/6[...]`, populated only from the peer's ADDITIONAL_IP4/6_ADDRESS notifies,
ikev2_notify.c:1177-1218; state in ikev2_impl.h:474-485).  If the COOKIE2 echoes back
(`ikev2_info_init_notify_recv`, informational.c:824-839), it restores the address the kernel SAs
still use, then migrates to the just-proven address.  This is RFC 4555 §3.6/§3.7 "responder-follow":
racoon2 initiates the probe, but it probes the **responder's** addresses to recover when the
link to the responder dies — it does not publish racoon2's own new address to anyone.

### Capability negotiation — responder advertises

- racoon2 pushes N(MOBIKE_SUPPORTED) in the responder's first IKE_AUTH response
  (`ikev2_responder_eap_auth_send`, ikev2_sa_auth.c:2733-2740).
- `ike_sa->mobike_supported` is set **only from a received** MOBIKE_SUPPORTED
  (ikev2_notify.c:167, 349, 1092) — i.e. MOBIKE apply/migrate logic is gated on the peer having
  advertised it, and there is no config override either way.

## What is NOT implemented / limits

- **Initiator-originated UPDATE_SA_ADDRESSES is not implemented.**  There is no site that
  constructs and sends an UPDATE_SA_ADDRESSES notify (a search of the tree for a push builder
  with `IKEV2_UPDATE_SA_ADDRESSES` finds only the receive/define side), and therefore no code
  that detects racoon2's own local address change — interface state, source-address acquisition,
  or an outbound NAT rebind — and drives a mobility exchange toward the peer.  racoon2 never
  tells a peer "I have moved."  It only ever follows a peer/kernel change.  (README.md:215-218
  states this explicitly: "responder-follow … initiator-originated updates not implemented —
  remote-access server role"; NEWS records it as "RFC 4555 MOBIKE responder".)
- **racoon2 does not advertise its own ADDITIONAL_IP4/6_ADDRESS.**  `extra_addr4/6` are filled
  only from the peer's notifies (for responder-follow); there is no builder that advertises
  racoon2's alternate addresses.
- **No config knob.**  RFC 4555 does not require one; MOBIKE is driven entirely by the peer's
  MOBIKE_SUPPORTED notify.  `natt_follow_mapping` (default off) is the only related tunable.
- **Single traffic direction semantics**: the migrate assumes a road-warrior shape (one
  tunnel, lease-provided inner address); there is no multi-Child/multihoming address-set
  bookkeeping beyond the single lease/selector pair harvested in one pass.

## Risks / open items

- **Discovery of racoon2's own mobility is the open design gap.**  To become a MOBIKE
  *initiator* that pushes updates, racoon2 needs (a) a trigger source — the kernel routing /
  source-preference change or an outbound mapping rotation — and (b) a new INFORMATIONAL request
  builder that carries N(UPDATE_SA_ADDRESSES) guarded by `mobike_supported`, plus (c) a
  hold-down so the address swap is committed only after the peer's ACK, and (d) an
  "I-AM-INITIATOR" alternate-address advertisement of racoon2's own addresses to support
  responder-follow *of* racoon2.  Items (b) reuses the existing `ikev2_informational_initiator_notify`
  path and the existing applier; (c) is the substantive new state (a pending-initiated move).
- **First-message race on follow**: the implicit detection keys on `ike_sa->mobike_supported`,
  which requires having seen the peer's notify — a message from a moved (post-auth) peer is
  integrity-checked before the compare, so an unauthenticated source is not an update.
- **Lease-based inner endpoint**: the migrate binds kernel SAD to the CP lease address; a
  road-warrior roaming to a network that cannot reach that lease (no host-internal routing)
  could strand the data path.  Not exercised in this note.
- **`natt_follow_mapping` off by default** means a peer NAPT rebind without an explicit
  update — against a MOBIKE-negotiated SA the *implicit* path (source-change on an IKE message)
  still covers it; the XFRM_MSG_MAPPING path only adds early detection when enabled.

## Test/validation status

The matrix row `ikev2-netns-mobike` (samples/linux-matrix/cases.tsv:34) drives charon with
`mobike = yes` (a **charon** knob, samples/linux-matrix/kinds/ikev2.sh:285 — it is not a racoon2
config keyword) against the iked responder and proves the negotiation knob, not a roam; the
`ikev2-netns-cookie2` row (cases.tsv:35) proves NO_ADDITIONAL_ADDRESSES/COOKIE2 processing.
The suite does **not** exercise an end-to-end racoon2-as-initiator roam, because that feature
does not exist.  A live roaming-*peer* proof is the iPhone/iOS peer exercising the
implicit/UPDATE path against the responder, as noted in NEWS.
