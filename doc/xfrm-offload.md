# XFRM-native features: mark, if_id, and hardware-accelerated offload

Status: **structures + Linux backend encoding landed** (`daa77da`, emit gate
refined in `11b5dc1`). Config
grammar wiring and the DGX Spark HW-offload bring-up are the next steps below.
This extends `struct rcpfk_msg` (lib/if_pfkeyv2.h) with the three XFRM-native
features PF_KEY cannot express, and the NETLINK_XFRM backend now emits them.

## What the structures support now

`struct rcpfk_msg` carries, and `lib/if_xfrm.c` emits on the SA path
(`XFRMA_MARK`, `XFRMA_IF_ID`, `XFRMA_OFFLOAD_DEV`) and the policy path
(`XFRMA_MARK`, `XFRMA_IF_ID`):

| field             | netlink attr        | meaning                                        |
|-------------------|---------------------|------------------------------------------------|
| `mark`/`mark_mask`| `XFRMA_MARK` (struct xfrm_mark) | flow mark + mask the kernel matches on SA/policy |
| `if_id`           | `XFRMA_IF_ID` (u32) | per-SA/policy interface/VRF identifier          |
| `offload_ifindex` / `offload_flags` / `offload_ifname` | `XFRMA_OFFLOAD_DEV` (struct xfrm_user_offload) | device (ifindex) + direction for crypto/stateless IPsec offload |

- The *BSD PF_KEY and loopback userspace backends have no equivalents and
  ignore these fields (they never read them).
- The emit is guarded (`#if defined(XFRMA_MARK) && defined(XFRMA_IF_ID)` /
  `#ifdef XFRMA_OFFLOAD_DEV`) so an older kernel UAPI header still compiles;
  on a kernel without the attr the field is simply not emitted.
- `offload_flags` is the XFRM_OFFLOAD_* direction bit (0 = outbound,
  `XFRM_OFFLOAD_INBOUND` for inbound), `offload_ifname` is resolved to an
  index via `if_nametoindex()` when `offload_ifindex` is 0. An offload SA is
  requested iff a device is named (non-zero `offload_ifindex` or non-empty
  `offload_ifname`); `offload_flags == 0` with a named device is a valid
  outbound request and is still emitted.

## Next implementation steps (not yet in tree)

1. **Config grammar** so an operator can set these per policy / child SA.
   Proposed (racoon2.conf, in the `policy {}` / `sa {}` blocks or a per-child
   `ipsec {}` section):
   ```
   policy pol {
       action auto_ipsec;
       ...
       mark { value 0x100; mask 0xff; }       # -> XFRMA_MARK
       if_id 1;                                # -> XFRMA_IF_ID
   }
   sa esp_e {
       offload { dev "ens2f0np0"; dir in; }    # -> XFRMA_OFFLOAD_DEV
       # mark / if_id can also be set here (inherited by the child SA)
   }
   ```
   This needs `lib/cftoken.l` + `lib/cfparse.y` grammar, `ike_conf.c`
   storage, and copying the fields onto the `rcpfk_msg` in the policy/add
   paths (`ike_pfkey.c`). The kernels-only fields are ignored (best-effort
   warn) on *BSD.

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

## References
- `lib/if_pfkeyv2.h` (struct rcpfk_msg, new fields)
- `lib/if_xfrm.c` (`add_xfrm_mark_ifid_attrs`, `add_xfrm_offload_attr`)
- Kernel UAPI: `struct xfrm_user_offload { int ifindex; uint8_t flags; }`,
  `struct xfrm_mark { uint32_t v, m; }` — layout varies by kernel version;
  the code uses the local header's definition.
