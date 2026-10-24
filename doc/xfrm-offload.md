# XFRM-native features: mark, if_id, and hardware-accelerated offload

Status: **structures + Linux backend encoding landed** (`daa77da`; the emit
was spuriously compiled out until `020e027` removed the dead `#ifdef XFRMA_*`
guards — `XFRMA_MARK`/`XFRMA_IF_ID`/`XFRMA_OFFLOAD_DEV` are enum constants,
not macros). The **config grammar** (mark/if_id on the policy, offload on the
SA; `lib/icketest` PASS) is wired; the DGX Spark HW-offload bring-up is the
remaining step below. This extends `struct rcpfk_msg` (lib/if_pfkeyv2.h) with
the three XFRM-native features PF_KEY cannot express, and the NETLINK_XFRM
backend now emits them.

## What the structures support now

`struct rcpfk_msg` carries, and `lib/if_xfrm.c` emits on the SA path
(`XFRMA_MARK`, `XFRMA_IF_ID`, `XFRMA_OFFLOAD_DEV`) and the policy path
(`XFRMA_MARK`, `XFRMA_IF_ID`):

| field             | netlink attr        | meaning                                        |
|-------------------|---------------------|------------------------------------------------|
| `mark`/`mark_mask`| `XFRMA_MARK` (struct xfrm_mark) | flow mark + mask the kernel matches on SA/policy |
| `if_id`           | `XFRMA_IF_ID` (u32) | per-SA/policy interface/VRF identifier          |
| `offload_ifindex` / `offload_flags` / `offload_ifname` | `XFRMA_OFFLOAD_DEV` (struct xfrm_user_offload) | device (ifindex) + direction for crypto/stateless IPsec offload |

- `mark` / `if_id` have no PF_KEY spelling and the *BSD PF_KEY and loopback
  userspace backends ignore them (never read). `offload_ifname`, however, has
  a real *BSD counterpart: `lib/if_pfkeyv2.c` emits `SADB_X_EXT_IF_HW_OFFL`
  from the name on FreeBSD (see below). Only the loopback backend ignores all
  of these.
- The emit is NOT `#ifdef`-guarded on the XFRMA_* names: `XFRMA_MARK` /
  `XFRMA_IF_ID` / `XFRMA_OFFLOAD_DEV` are **enum constants** in
  `<linux/xfrm.h>`, not macros — an `#ifdef XFRMA_*` guard is always false and
  silently compiled the offload out on every kernel (it did). `lib/if_xfrm.c`
  includes `<linux/xfrm.h>` and emits unconditionally.
- `offload_flags` is the XFRM_OFFLOAD_* direction bit (0 = outbound,
  `XFRM_OFFLOAD_INBOUND` for inbound), `offload_ifname` is resolved to an
  index via `if_nametoindex()` when `offload_ifindex` is 0. An offload SA is
  requested iff a device is named (non-zero `offload_ifindex` or non-empty
  `offload_ifname`); `offload_flags == 0` with a named device is a valid
  outbound request and is still emitted.

## Matrix coverage (live kernels)

Two `samples/linux-matrix` rows (`kinds/i2ixfrm.sh`) exercise these features
against real kernels, iked<->iked in private netns with their own daemons. Both
run on the Ubuntu and Fedora lanes and in the kernel-version lane's quick
shard (5.15, 6.1, newest):

- `i2ixfrm-mark`: policy `mark { value 0x42; mask 0xff; }` on both seats. The
  row checks that every ESP state and ESP policy carries `mark 0x42/0xff`. That
  makes the kernel accept XFRMA_MARK on ALLOCSPI and NEWSA/UPDSA on that kernel,
  instead of leaving it to the unit-pinned bytes. Marked echos (`ping -m`, with
  inbound ESP marked by nft/iptables because an inbound SA lookup matches
  skb->mark) have to move both seats' SA counters, and unmarked echos must not.
- `i2ixfrm-offload`: the responder's `offload {}` names a **netdevsim** port
  (the kernel's xfrmdev_ops test device). Both responder ESP states must
  report `crypto offload parameters: dev <port> dir in|out`, and netdevsim's
  ipsec debugfs must count them. netdevsim does not encrypt on the wire, so this
  proves the XFRMA_OFFLOAD_DEV binding, not a real NIC fast path. The row
  is `gate=nsim`. run.sh skips it only when a hand-installed offload SA is
  refused, and the SKIP line prints that refusal (module absent, or the kernel
  drops the binding). Anywhere the probe succeeds, the row must pass.

Real hardware (the DGX Spark bring-up below) is still a box-only step.

## Next implementation steps

1. **Config grammar — DONE** (`lib/cftoken.l`/`cfparse.y`, `lib/cfsetup.{h,c}`,
   `iked/ikev2_child.c`). An operator sets the flow selector and offload with:
   ```
   policy pol {
       action auto_ipsec;
       ...
       mark { value 0x100; mask 0xff; };      # -> XFRMA_MARK (v = value & mask)
       if_id 1;                                # -> XFRMA_IF_ID
   }
   sa esp_e {
       offload { dev "ens2f0np0"; dir in; };   # -> XFRMA_OFFLOAD_DEV (dir in=2/out=0)
   }
   ```
   Design decisions (all verified in `lib/icketest`, `PASS`):
   - **mark / if_id live on the POLICY** (the child flow), copied from
     `selector->pl` by a single `spmd set_mark_ifid()` onto EVERY kernel
     policy op — SPDADD/update (`spmd_nonfqdn_sp_add`, `sl_to_rc_wo_addr`),
     delete-by-index (`spmd_spd_delete`, `spmd_spd_match_delete`), `migrate`,
     and the FWD clone — plus the larval GETSPI and final `ikev2_sadb_update`
     SAs. The policy and both SAs share the mark so `xfrm_policy_byid` and
     the state lookup match the same marked flow (otherwise: blackhole or
     ESRCH on delete). Deliberately NOT on `sa {}`: each CFD_ key decodes
     into a single dst type.
   - **offload lives on the `sa {}` block** (`sa_esp`, ESP only) and is
     PER-DIRECTION: each kernel SA carries its natural flag — the inbound SA
     gets `XFRM_OFFLOAD_INBOUND`, the outbound SA 0. Config `dir` is a
     which-direction filter (`dir in` = inbound only, `dir out` = outbound
     only, omitted = both); `ikev2_delete_sa` and `spmd` both carry the mark.
   - `mark_mask` reads as a full u32 (`rcf_fix_u32`), so `0xffffffff` is
     accepted (not INT-clamped); an omitted mark mask defaults to
     `0xffffffff` (what `ip xfrm` shows), so `mark { value 0x100; }` is not a
     no-op.
     An **explicit `mask 0`** matches nothing, so it is rejected instead of
     being silently rewritten to a full mask.
   - **Reserved words:** the grammar adds the global tokens `mark`, `if_id`,
     `offload`, `value`, `mask`, `dev`, `dir`, `in` and `out`. They are now
     keywords anywhere in a config (quote them if used as a name/string).
   - `XFRMA_OFFLOAD_DEV` is refused for non-ESP states inside the emitter
     itself (`add_xfrm_offload_attr`), not only by the ESP-filtering caller.
   - Selector family: a wildcard side takes the specified peer's family; a
     mixed pair of *specified* addresses is rejected (EINVAL); a selector
     whose both sides are wildcards defaults to **AF_INET**, so an IPv6-only
     "any" policy must spell `::/0` on at least one side with a family-
     specific peer, or it installs a v4-wildcard policy.
   - Fail-closed: unknown block keys, bad `dir`, unterminated blocks, and an
     **offload block without a `dev`** (silent no-op) reject the whole config;
     every new CFD_ has a registered `rcf_tdf` fix; an over-long device name
     is rejected.
   - **IKEv1:** the mark/if_id flow selector is copied onto the IKEv1 larval
     and add/update SAs too (`pk_set_mark_ifid` in `iked/ikev1/pfkey.c`), so a
     marked/if_id policy stays binding. **Offload is IKEv2-ESP only** — the
     IKEv1 add/update path never requests XFRMA_OFFLOAD_DEV, so `offload {}`
     on a child used by IKEv1 is accepted config that does not offload (no
     error; IKEv1 is out of scope and offload is a new IKEv2 feature).

2. **HW-offload bring-up on DGX Spark** (the test target the user named).
   - **Precondition gate:** only enable offload after `ethtool -k <dev>`
     reports `esp-hw-offload: on` (or `rx`/`tx`). The review's earlier BUGS
     note ("do not add XFRMA_OFFLOAD_DEV until ethtool shows esp-hw-offload")
     is exactly this gate. DGX Spark ships ConnectX-7/MLNX (or BlueField);
     confirm `ethtool -k` + `lspci` before relying on it.
   - **Bring-up script** (box, as root):
     ```
     ethtool -k <dev> | grep esp                       # must say on
     ip link set <dev> up
     # get a phase-1 pair up with the offloaded SA:
     ip xfrm state ...  # or run a matrix row with offload flags
     ```
   - **Verification of a real offload** (not software crypto):
     - `ip -s xfrm state` while pumping traffic: the SA's `soft limit`
       byte/use counters should advance on the hardware SA path;
     - `ethtool -S <dev>` shows the HW crypto/ESP counters (e.g.
       `esp_in_packets` / `esp_out_bytes` on mlx5) advancing;
     - `perf stat` / `top` CPU: near-zero ksoftirqd/xfrm CPU on the ESP path
       (software fallback would burn CPU);
     - sanity: `ip xfrm state` still lists the SA and ICV/decrypt errors are
       zero in `ip -s xfrm`.
   - **Matrix row**: add a `gate=box` row that negotiates an ESP child with
     `offload { dev …; }` set, verifies the XFRMA_OFFLOAD_DEV attribute is
     accepted by the kernel (EEXIST-class errors treated as idempotent) and an
     offloaded state exists, and that dataplane ICMP crosses. This is the live
     proof; do not mark it green from a config that merely parses.

3. **Safety/limits**:
   - Offload requires the crypto algorithm the NIC supports (AES-GCM / AES-CBC
     with the matching keysize). A mismatch is a kernel `EINVAL`/`EOPNOTSUPP`;
     fail the install loudly (xfrm_seterror), do not silently fall back to
     software.
   - `if_id` and `mark` are per-policy/flow; copy them onto BOTH the policy and
     the child SA consistently or the kernel won't match the flow.
   - These are XFRM-only; never pretend a *BSD build honored them.

## FreeBSD IPSEC_OFFLOAD portability (how this maps onto PF_KEY)

The *BSD leg is now **wired in `lib/if_pfkeyv2.c`**: when `offload_ifname` is
set, `rcpfk_set_sadb_x_if_hw_offl()` appends the `SADB_X_EXT_IF_HW_OFFL`
extension to `SADB_ADD`/`SADB_UPDATE` (SA path) and `SADB_X_SPDADD` (policy
path), under `#ifdef SADB_X_EXT_IF_HW_OFFL`. Same fail-loud rule as Linux: an
ifindex-only offload request (no name) or a build whose PF_KEY ABI predates
`SADB_X_EXT_IF_HW_OFFL` refuses the SA rather than silently installing a
software one. Verified to compile against FreeBSD 15.1's real `pfkeyv2.h`.

FreeBSD's inline IPsec offload (NVIDIA-sponsored, 2024 → GENERIC, mlx5/
ConnectX-6+, IPv4 AES-GCM transport + UDP-ESP/NAT-T) is NOT a kernel-only
property — it is driven from userspace through PF_KEY extensions, which is
what makes it the same *class* of feature as the Linux XFRM offload this file
describes:

- `SADB_X_EXT_IF_HW_OFFL` (`struct sadb_x_if_hw_offl { u16 len; u16 exttype;
  u32 flags; u8 if[32]; }`), set
  via `setkey -hwif ifname` on `SADB_ADD` / `SADB_X_SPDADD`, restricts SP/SA
  offload to a named interface. (2024 commit, present in 15.0+ / 16.0-CURRENT;
  not in older branches — hence the `#ifdef` fallback.)
- `SADB_X_EXT_LFT_CUR_SW_OFFL` / `SADB_X_EXT_LFT_CUR_HW_OFFL` report
  software-vs-hardware offload lifetime counters per SA (the FreeBSD
  analogue of "is it really on the NIC?" — cf. the `ip -s xfrm state` /
  `ethtool -S` evidence this file's DGX-Spark step wants).

Why the rcpfk field is the right portable shape:

- **`offload_ifname` maps directly onto FreeBSD's name-based extension.**
  FreeBSD's wire format proves the interface is selected by NAME, not
  ifindex; on Linux we resolve that name via `if_nametoindex()` into
  `XFRMA_OFFLOAD_DEV.ifindex`. So keeping `offload_ifname` as the portable
  carrier (with `offload_ifindex` a Linux-resolved convenience) was the
  correct call, not an accident.
- **Direction is Linux-meaningful only.** XFRM offload is opt-in and each SA
  carries an explicit direction bit (`XFRM_OFFLOAD_INBOUND`, 0 = outbound).
  FreeBSD inline offload is bidirectional on the named NIC and is OFFERED to
  every capable driver by default unless `-hwif` restricts it — an SA can be
  hw-offloaded without any userspace request. So `offload_flags` (direction)
  and the "offload only when a device is named" gate are Linux semantics;
  the *BSD backend must not read offload_flags and cannot suppress FreeBSD's
  automatic offer.
- **mark / if_id have no FreeBSD PF_KEY counterpart** (no FW_MARK / VRF-like
  per-SP id) — permanently Linux-native, ignored on *BSD.
- **Same failure rule both sides:** FreeBSD mlx5 offload is AES-GCM transport
  (+NAT-T) only; an SA whose algorithm/mode the NIC cannot accelerate must
  fail loudly (kernel `EOPNOTSUPP`), never silently fall back to software.

The *BSD PF_KEY backend emits `SADB_X_EXT_IF_HW_OFFL` from `offload_ifname`
(`lib/if_pfkeyv2.c`, first wired in `9c241ab`), guarded by the extension's `#ifdef`
(same reason: 15.x/16 have it, 14 does not, and failing loud beats a silent
software SA there). The SW/HW counter-extension decode
(`SADB_X_EXT_LFT_CUR_SW_OFFL` / `SADB_X_EXT_LFT_CUR_HW_OFFL`) is a future
SADB_DUMP-side step for verification.

## References
- `lib/if_pfkeyv2.h` (struct rcpfk_msg, new fields)
- `lib/if_xfrm.c` (`add_xfrm_mark_ifid_attrs`, `add_xfrm_offload_attr`)
- Kernel UAPI: `struct xfrm_user_offload { int ifindex; uint8_t flags; }`,
  `struct xfrm_mark { uint32_t v, m; }` — layout varies by kernel version;
  the code uses the local header's definition.
