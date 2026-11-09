# RFC 4555 MOBIKE mobility — design note & validation

Status: **partial — but both roles are now implemented.**  The roaming-*follower*
side (implicit update on a peer source change, explicit UPDATE_SA_ADDRESSES accepted,
NAT-T mapping follow, responder-follow COOKIE2 probing) is implemented.  The
roaming-*initiator* push side — racoon2 detecting its OWN address change and actively
sending UPDATE_SA_ADDRESSES — is implemented as the `mobike_initiate (on|off)` knob
(default off, RFC 4555 §3.5): on a local-address change (rtnetlink event, Linux) iked
asks the kernel for the new source address and, when it differs, sends an INFORMATIONAL
UPDATE_SA_ADDRESSES (+NAT_DETECTION) and commits the migration on the peer's reply
(abandon on timeout).  `mobike_initiate` and `natt_follow_mapping` (default off; gates
only the XFRM_MSG_MAPPING path) are the two relevant tunables; MOBIKE follow handling is
otherwise active whenever the peer advertises MOBIKE_SUPPORTED.
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

The **initiator push role** is the mirror image and is implemented (config-gated,
`mobike_initiate on`): racoon2 notices *it* has acquired a new source address (interface
came up, NAT mapping rotated), starts an INFORMATIONAL exchange carrying
N(UPDATE_SA_ADDRESSES) plus NAT_DETECTION, and only commits the endpoint change after the
peer acknowledges (timeout puts the old address back).  The responder-follow probe (below)
is a separate path aimed at alternate addresses of the **peer**.

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

- **Initiator-originated UPDATE_SA_ADDRESSES: implemented, config-gated.**  `mobike_initiate on`
  (default off) constructs and sends an UPDATE_SA_ADDRESSES notify on racoon2's own local-address
  change (interface state / source-address acquisition / outbound NAT rebind), drives the
  INFORMATIONAL exchange toward the peer, and commits the endpoint change on the reply (abandon on
  timeout).  This supersedes the earlier "responder-follow … initiator-originated updates not
  implemented" note: the follow half and the initiator half are both in tree.
- **racoon2 does not advertise its own ADDITIONAL_IP4/6_ADDRESS.**  `extra_addr4/6` are filled
  only from the peer's notifies (for responder-follow); there is no builder that advertises
  racoon2's alternate addresses.
- **Config knobs** (both default off): `mobike_initiate` (initiator-originated push, RFC 4555
  §3.5) and `natt_follow_mapping` (gates only the XFRM_MSG_MAPPING path).  Follow handling
  itself is driven by the peer's MOBIKE_SUPPORTED notify.
- **Single traffic direction semantics**: the migrate assumes a road-warrior shape (one
  tunnel, lease-provided inner address); there is no multi-Child/multihoming address-set
  bookkeeping beyond the single lease/selector pair harvested in one pass.

## Risks / open items

- **Discovery of racoon2's own mobility is implemented** (`mobike_initiate on`,
  RFC 4555 §3.5): (a) the rtnetlink local-address event is the trigger, (b)
  `ikev2_mobike_local_update` builds and sends the INFORMATIONAL
  UPDATE_SA_ADDRESSES (+NAT_DETECTION) and folds in the kernel's new source
  address, and (c) a hold-down commits the endpoint change on the peer's ACK
  or abandons on timeout.  The still-open piece is (d) advertising racoon2's
  OWN alternate addresses (`extra_addr`) to support responder-follow *of*
  racoon2; the follow half and the initiator push half are both in tree.
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
The suite does **not** yet have a dedicated racoon2-as-initiator roam row (the
feature exists as `mobike_initiate on`, RFC 4555 §3.5); a live roaming-*peer* proof is the
iPhone/iOS peer exercising the implicit/UPDATE path against the responder, as noted in NEWS.

## MOBIKE and reconnects over RFC 9329 TCP

**Where ESP goes (deliberate):** for a tcp_encap SA only IKE rides the TCP
stream.  Child ESP stays UDP-encapsulated on 4500/4500 (or kernel espintcp
when `esp_tcp_encap` is on), both before and after a MOBIKE move.  The
consequence: on a path that blocks UDP entirely, a tcp_encap SA *without*
`esp_tcp_encap` keeps IKE alive but has no data plane.  Use `esp_tcp_encap`
there; it is off by default.

**Responder re-binding (RFC 9329 s7):** a TCP peer that loses its connection
reconnects and continues the IKE_SA on the new stream.  Replies are routed by
the SA's remote address:port (the client's TCP source port), so:

- *address changed* -- the integrity-verified message is an implicit or
  explicit MOBIKE update, handled by `ikev2_mobike_apply()` (ESP migrated,
  NAT-T ports kept at 4500);
- *same address, new stream* -- `ikev2_tcp_rebind()` moves only the SA's
  remote port (and any armed retransmit destination) to the new live stream;
  ESP is untouched.  Initiator SAs and non-tcp_encap SAs are never re-bound.
- *address changed over TCP* -- both steps run, in that order, on the same
  message: `ikev2_mobike_apply()` moves the SA (and ESP) to the new address,
  then `ikev2_tcp_rebind()` finds the address now equal and moves the remote
  port to the new stream's source port, so replies leave on the stream the
  update arrived on.

The old stream is not closed by the SA (another IKE_SA may share it); it is
reaped when the peer closes it or a send on it fails.  The re-bind runs on
INFORMATIONAL exchanges (the liveness check a reconnecting peer sends);
`tcpsrvtest` covers every branch.
