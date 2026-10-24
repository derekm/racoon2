# Successor to `struct rcpfk_msg`: an XFRM-native kernel-management container

Status: **design, not implemented**. `RCPFK_ABI_VERSION` (lib/if_pfkeyv2.h)
formally versions today's container. This note designs the replacement, so a
fourth backend or the next XFRM feature does not have to squeeze one more
field into a struct shaped like PF_KEYv2.

## Why the current container has to go

`struct rcpfk_msg` is one flat struct used for every SAD and SPD operation in
both directions (request and kernel event). That causes concrete problems:

- **Mixed lifetimes.** It holds request inputs (keys, lifetimes), reply outputs
  (`eno`, `estr`), event payloads (`expired`, `sa2_*` for MAPPING) and
  transport state (`so`, `seq`, `flags`). The WAITREPLY scratch routing in
  `xfrm_read_one` exists because a reply could clobber the caller's request
  container.
- **PF_KEY vocabulary.** It uses `satype` rather than the IP protocol,
  `slid`/"spid", `pref_src`, `ipsec_level`, and `samode` drawn from
  `IPSEC_MODE_*`. Every XFRM call translates back and forth
  (`rcpfk_satype_to_proto`, `fill_selector`), and each translation has been
  the site of a bug (mixed-family selectors, AF_INET wildcard defaulting).
- **Bolted-on XFRM features.** `mark`/`mark_mask`, `if_id` and `offload_*` are
  appended at the end. The PF_KEY and userspace backends ignore them
  silently, and "is this field set" uses sentinels (`mark_mask != 0`,
  `offload_flags == 0` meaning outbound, not unset).
- **One SA per container.** An IKE child is an SA *pair* plus up to three
  policies (in/out/fwd), but they are installed by separate calls that share
  nothing. Rollback on partial failure is left to each caller.
- **Pointer-into-self addresses.** `sa_src` points at `sa_src_storage`, so
  copying the struct by value silently aliases the original.

## Shape of the successor

Separate objects, each mapped 1:1 to an XFRM concept. PF_KEY becomes an adapter
that lowers them, not the model they are built from.

```c
struct km_addr   { sa_family_t family; union { struct in_addr v4; struct in6_addr v6; } a; };
struct km_sel    { struct km_addr src, dst; uint8_t src_plen, dst_plen;
                   uint8_t proto; uint16_t sport, dport; uint32_t ifindex; };
struct km_mark   { uint32_t v, m; };                    /* present iff km_has(MARK) */
struct km_lft    { uint64_t soft_bytes, hard_bytes, soft_add, hard_add,
                   soft_use, hard_use; };               /* 0 = none (no ~0 sentinel) */
struct km_alg    { int id; uint16_t key_bits; uint16_t icv_bits; uint8_t key[64]; };

struct km_state {                 /* == xfrm_usersa_info + attributes   */
	struct km_addr saddr, daddr; uint32_t spi; uint8_t proto; /* IPPROTO_ESP/AH/COMP */
	uint8_t mode;                 /* XFRM_MODE_* */
	uint32_t reqid, if_id; struct km_mark mark;
	struct km_alg enc, auth, aead;  /* exactly one of aead or enc(+auth) */
	struct km_lft lft; uint32_t replay_window; uint32_t flags; /* XFRM_STATE_* incl. ESN */
	struct { uint16_t sport, dport; uint8_t type; } encap;     /* NAT-T, type 0 = none */
	struct { uint32_t ifindex; uint8_t dir; } offload;          /* present iff km_has(OFFLOAD) */
	uint32_t present;             /* KM_HAS_* bitmap: no sentinel values */
};

struct km_tmpl   { struct km_addr saddr, daddr; uint8_t proto, mode; uint32_t reqid; uint8_t optional; };
struct km_policy { struct km_sel sel; uint8_t dir; /* XFRM_POLICY_IN/OUT/FWD */
                   uint32_t index, priority, if_id; struct km_mark mark;
                   uint8_t action; struct km_tmpl tmpl[4]; uint8_t ntmpl; uint32_t present; };

/* one IKE child = one transaction: both states + their policies */
struct km_child  { struct km_state in, out; struct km_policy pol[3]; uint8_t npol; };

/* transport is separate from data: one completion record per op */
struct km_op     { uint32_t seq; int type; int eno; char estr[128];
                   void (*done)(struct km_op *, void *ctx); void *ctx; };
```

Rules:

1. **No sentinels.** Optional attributes use a `present` bit (`KM_HAS_MARK`,
   `KM_HAS_IFID`, `KM_HAS_OFFLOAD`, `KM_HAS_ENCAP`). A backend that cannot
   honour a present attribute must fail the op with `EOPNOTSUPP` instead of
   dropping it. This is the userspace backend's loud-failure rule, applied
   generally.
2. **No self-pointers.** Addresses are values (`km_addr`), so objects copy
   safely. `sockaddr` only appears at the boundary with iked and spmd.
3. **Requests, replies and events are different types.** An event is a
   `km_state` or `km_policy` plus a `km_event` header (`type`, `hard`,
   `mapping_new` for NAT-T). A reply is a `km_op`. The op table in if_xfrm.c
   (keyed by seq) already exists and becomes `km_op` directly.
4. **Child-level transaction.** `km_child_install()` adds the states, then the
   policies. On the first failure it deletes what it already installed and
   reports a single error. This replaces the per-caller rollback in iked and
   spmd.
5. **Capability query.** `km_caps()` returns which `KM_HAS_*` attributes and
   modes the backend supports (XFRM: all; PF_KEY: no mark or if_id, offload
   only on FreeBSD 14+; userspace: whatever the dataplane advertises). The
   config loader can then reject `mark {}` on a PF_KEY build at parse time
   instead of at install time.

## PF_KEY as an adapter

`lib/km_pfkey.c` lowers each object to SADB messages:

- `proto`: `satype` via the existing `rct2ipproto_satype` inverse. This keeps
  the existing behaviour of aborting on an unknown satype.
- `mode`: `IPSEC_MODE_*`.
- `km_sel` is split into SADB_EXT_ADDRESS_SRC/DST with prefix lengths.
- `KM_HAS_OFFLOAD` lowers to `SADB_X_EXT_IF_HW_OFFL` where available, and
  otherwise to `EOPNOTSUPP`.
- `KM_HAS_MARK` and `KM_HAS_IFID` always give `EOPNOTSUPP` on PF_KEY.

## Migration plan (incremental, every step shippable)

1. Add `km_*` types and a converter `rcpfk_msg <-> km_state/km_policy` in
   lib/rcpfk_util.c, with round-trip unit tests over every field, including
   the attributes that today rely on sentinels.
2. Port if_xfrm.c internals to build netlink messages from `km_*`. Keep
   `rcpfk_send_*` as thin wrappers that convert. The xfrmnltest byte-level
   tests must stay green unchanged, which proves wire identity.
3. Add `km_child_install()` and switch iked's child install path to it, then
   spmd's policy path.
4. Port the userspace and PF_KEY backends to the adapter shape.
5. Remove `struct rcpfk_msg` and bump `RCPFK_ABI_VERSION` to 2 along with the
   libtool soname (the coordinated deploy described in lib/Makefile.am).

Every step keeps the netns matrix green. Step 2 is the risky one and is gated
by the existing wire-level tests.

## Why this is not implemented yet

Steps 2 to 5 touch every kernel call site in iked (ikev2_child.c, ikev1
pfkey.c, ikev2_rekey.c) and spmd. That means weeks of work and a full matrix
re-proof on all three backends and every OS lane. It also changes the
libracoon ABI, so it needs Derek's coordinated soname bump. Step 1 can land
independently.
