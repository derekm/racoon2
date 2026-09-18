# iked<->iked netns ADDKE matrix — bring-up harness (Fedora, wip)

Goal: continuously verify racoon2 PQC ADDKE end-to-end WITHOUT a phone or a
charon that has ML-KEM (neither WSL 5.9.13 nor Fedora RPM strongSwan 6.0.7
exposes mlkem768; only other WITH_ADDKE racoon2 can offer/select type-6).
So the initiator is itself a racoon2, running in the netns, offering
esp_addke_alg; the responder is a passive racoon2 in the host namespace.

## Status (2026-09-18): 3 real fixes landed; netns initiator still not green

Three real bug fixes committed:
- `RACOON2_ADMIN_SOCK` env override (iked/admin.c, `c4a32d4`) — two ikeds on one
  host collide on the fixed ADMINSOCK_PATH; the second to bind dies (a
  bind-fail, NOT the SEGV — keep the two distinct).
- `memset(&rcpfk_msg,0,...)` in `ike_pfkey.c sadb_poll` (`71a6a5b`) — fixed the
  iked-as-initiator-in-netns SEGV (unset `sa2_src` was garbage; `isakmp_initiate`
  passed it non-NULL through `if (src2)` → `rcs_getsalen`).  Verified by core
  backtrace.
- minting a fresh `sadb_new_seq()` for the acquire-initiated child GETSPI
  (`ikev2.c`, `75de6ee`) — the acquire's seq is 0 (netlink backend never sets
  it), so if_xfrm invented an unmatchable netlink seq; the child now issues a
  proper GETSPI request ("SADB_GETSPI ... no corresponding request" is gone).

Live harness state: both stacks start, `IKE_SA_INIT` is sent/received on both
sides (`INI_`/`RES_IKE_SA_INIT_SENT`) — but the initiator's netns still does
not reliably receive the responder's 248-byte reply and advance to IKE_AUTH;
ESP SAD stays 0 on both sides (the `bringup.sh` 40s gate reports NOT UP).  The
GETSPI-seq bug is fixed in code; the remaining live blocker is the netns
initiator's inbound IKE reception/advance, not yet root-caused.

### GETSPI diagnosis (review-refined, next focused debug)

`sadb_getspi_callback` matches `param->seq` against the `sadb_request` list.
But racoon2-as-initiator mints the child GETSPI with `req->request_msg_seq`
**taken from the kernel ACQUIRE** (`ikev2.c:1044`), and a netlink ACQUIRE often
carries **seq 0**.  `lib/if_xfrm.c` (`nlmsg_seq = rc->seq ? rc->seq : ++xfrm_seq`,
comment "iked matches replies by param->seq (0x4000000+). Do not invent one.")
only invents a seq when rc->seq is 0 — and `sadb_new_seq()` starts at
`0x4000000`.  So if the acquire arrived with seq 0, netlink invents a seq and
the callback can never match the request.  Also the single-slot `pending_*`
means a second GETSPI (acquire-vs-ikedctl) can drop the real reply.

Plan: log the acquire seq, the GETSPI send seq, `nlmsg_seq`, and the
`sadb_find_by_seq` argument on the initiator child path; if the acquire seq is
0, assign `sadb_new_seq()` on that path before touching spmd, and check the
single-slot pending vs a second acquire.

## Gotchas (each empirically learned, a separate bug)

- **Two ikeds on one host**: distinct `RACOON2_ADMIN_SOCK` per iked.  Pass via
  `env VAR=x iked` inside `ip netns exec` — bare `VAR=x cmd ip netns exec`
  treats it as the command and fails to exec.
- spmd/iked socket path under `/run/racoon2` can ENOENT on bind; use /tmp.
- spmd_password must reference an existing spmd.pwd (production one works).
- IKE transmit cannot send off a `0.0.0.0`-bound socket; bind the interface to
  the concrete address for BOTH sides (`ike { "192.0.2.2"; }`).
- Stale iked/spmd from a prior run hold :500/:4500 → the fresh responder
  `bind: Address already in use` and never replies.  Kill by the daemon sbin
  path before each run — NEVER pkill a pattern present in the runner's own
  command line (it SIGKILLs itself).
- The auto_ipsec SPD on the initiator netns drops inbound IKE UDP before iked
  sees it; install explicit 500/4500 UDP allow rows (in/out/fwd) on the netns
  and the host after both stacks are up (mirrors kinds/ikev2.sh).  NOTE: spmd
  does NOT flush all xfrm at boot — `spmd_spd_flush` only deletes spmd-owned
  SPDs (the Linux spmd comment even says it never flushes on exit); startup
  ADDS the auto_ipsec rows.  The ordering requirement is that the allow rows
  co-exist with spmd's SPD management and take precedence (auto_ipsec overlap),
  not a global flush.  Prove the rows with `ip xfrm policy list` after adding.

## Blocker (next focused debug — GETSPI, not the crash)

The initiator SEGV is fixed and verified (both C commits are bugfixes).  The
remaining blocker is the child `SADB_GETSPI` seq mismatch above — log the seqs
and, if the acquire arrives with seq 0, mint `sadb_new_seq()` on the initiator
child path before spmd.  Only after a baseline CHILD is installed (ESP states
+ IKE_AUTH on both sides) do the ADDKE assertion: child rekey offers type-6
(both `esp_addke_alg { mlkem768; };`), responder echoes type-6 + 16441,
IKE_FOLLOWUP_KE decaps, new SPI takes packets, no DELETE IKE_SA.  Do not call
the matrix green (and do not iPhone-test) until that child install is proven
from logs.

## Files
- initiator.conf / responder.conf — the two fqdn-identity PSK configs.
- bringup.sh — root bring-up; stops/restores production iked+spmd, kills
  stale i2i daemons, sets up netns+veth, both stacks, UDP-allow SPD, triggers
  `ikedctl -s /tmp/iked.sock-i2i establish-sa isakmp inet 192.0.2.2 192.0.2.1`.
