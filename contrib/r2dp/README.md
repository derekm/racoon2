# r2dp — external dataplane control protocol for racoon2

r2dp lets racoon2's IKE daemon (`iked`) and policy daemon (`spmd`) drive an
**external forwarder** — e.g. a standard DPDK IPsec app — instead of the kernel.
racoon2 only needs a small backend (`--with-km-backend=r2dp`); the forwarder is
a separate project that speaks a PF_KEY-shaped protocol over a unix socket.

    iked / spmd ──(rcpfk_* ABI)── if_r2dp.c ──(r2dp, SOCK_SEQPACKET)── forwarder (DPDK)

## Status
**M0 done** (protocol, client/server lib, mock forwarder, racoon2 backend, and a
real two-peer IKEv2 test). **M1+ (the DPDK forwarder) not started.**
See `docs/MILESTONES.md` for the full plan, exit gates, and findings.

## Layout
| path | what |
|---|---|
| `include/r2dp/proto.h` | the wire contract (algorithms = IANA IKEv2 IDs, protocols = IP proto numbers) |
| `include/r2dp/client.h`, `libr2dp/` | transport, validation, address helpers (client + server side) |
| `tools/mockfwd.c` | `r2dp-mockfwd`: protocol-faithful forwarder with no dataplane |
| `shim/if_r2dp.c` | the racoon2 backend (single source of truth) |
| `patches/racoon2-r2dp-backend.patch` | applies to racoon2 `2fd758a`: 52 glue lines + `lib/if_r2dp.c` |
| `tests/` | `test_proto`, `test_mock`, `shim_contract` (meson); `e2e/` (two-peer IKEv2, needs root) |
| `build.sh` | deps / check / build / test / sanitize / e2e / milestones |

## Quick start
    ./build.sh deps -m 0                 # or: ./build.sh check -m 0
    ./build.sh test -m 0 --racoon2 /path/to/racoon2     # unit + contract tests
    sudo ./build.sh e2e --racoon2 /path/to/racoon2      # clean clone + patch + build + IKEv2 over veth

The racoon2 checkout passed to `--racoon2` is only read (the e2e flow works on a
scratch clone). Run the daemons against a forwarder with `R2DP_SOCK=<path>`
(default `/run/r2dp/r2dp.sock`) and optionally `R2DP_ROLE=iked|spmd`.

> If the scripts lost their executable bit (e.g. after a download/unzip):
> `chmod +x build.sh tests/e2e/*.sh`, or run them as `bash build.sh ...`.
