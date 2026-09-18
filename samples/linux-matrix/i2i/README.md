# iked<->iked netns ADDKE matrix — bring-up harness (Fedora, wip)

Goal: continuously verify racoon2 PQC ADDKE end-to-end WITHOUT a phone or a
charon that has ML-KEM (neither WSL 5.9.13 nor Fedora RPM strongSwan 6.0.7
exposes mlkem768; only other WITH_ADDKE racoon2 can offer/select type-6).
So the initiator is itself a racoon2, running in the netns, offering
esp_addke_alg; the responder is a passive racoon2 in the host namespace.

## Status (2026-09-18): past IKE_SA_INIT; child GETSPI seq tracking in netns

Two real bugs fixed (committed):
- `RACOON2_ADMIN_SOCK` env override (iked/admin.c) — two ikeds on one host
  collide on the fixed ADMINSOCK_PATH; the second to bind dies.
- `memset(&rcpfk_msg,0,...)` in `ike_pfkey.c sadb_poll` — the stack msg was
  only partially set, so an unset `sa2_src` was garbage; `sadb_acquire_callback`
  passed it non-NULL to `isakmp_initiate` → `rcs_getsalen` SEGV.  That was THE
  iked-as-initiator-in-netns crash (never exercised by the matrix before).

The harness now: starts both stacks, `IKE_SA_INIT` completes (initiator stops
retransmitting, gets the 248 B response), and the initiator proceeds to mint
its child inbound SPI.  Current blocker: the initiator's `SADB_GETSPI` response
comes back `does not have corresponding request (ignored)` + `sadb_poll:
unknown error`, so the child can't be installed and IKE_AUTH never fires (ESP 0
on the responder).  That is the netns PFKEY seq tracking between the initiator
iked's GETSPI and the netns spmd's reply — next focused debug.  (Backtrace for
the crash was captured via core_pattern=/tmp/r2core-%e-%p + gdb: the frame was
rcs_getsalen<-rcs_sadup<-isakmp_initiate<-sadb_acquire_callback.)

## Gotchas (all learned empirically, each was a separate bug)

- **Two ikeds on one host collide on the fixed ADMINSOCK_PATH**
  (/var/run/iked.sock) and the second dies.  Run each with a distinct
  `RACOON2_ADMIN_SOCK` (iked/admin.c env override).  Pass via `env VAR=x iked`
  inside `ip netns exec` — bare `VAR=x cmd ip netns exec` treats it as the
  command and fails to exec.
- spmd/iked socket path under `/run/racoon2` can ENOENT on bind; use /tmp.
- spmd_password must reference an existing spmd.pwd (production one works).
- The IKE transmit path cannot send off a `0.0.0.0`-bound socket; bind the
  interface to the concrete address for BOTH sides (initiator 192.0.2.2,
  responder 192.0.2.1).  `ike { "192.0.2.2"; }`.
- Stale iked/spmd from a prior run hold :500/:4500 → the fresh responder
  `bind: Address already in use` and never replies.  `pkill -9 -f r2i2i_boot`
  before each run.
- The initiator netns SPD (auto_ipsec) drops inbound IKE UDP before iked sees
  it; install explicit 500/4500 UDP allow rows in the netns (in/out/fwd) and
  on the host, mirroring kinds/ikev2.sh.
- Those UDP-allow rows must be added AFTER spmd finishes — spmd flushes ALL
  xfrm policies at startup, wiping rows installed before it.  Add them after
  both stacks are up.  (No rows at all → IKE_SA_INIT retransmits forever;
  rows too early → same, because spmd flushed them.)

## Blocker (next focused debug)

The initiator crashes (SIGSEGV, nondeterministic — a gdb -batch run usually
MASKs it by slowing the responder reply; plain runs crash after it has
installed ~2 netns ESP states).  The initiator log shows
`ike_pfkey.c:217 log_rcpfk_error: sadb_poll` and
`SADB_GETSPI ... does not have corresponding request (ignored)` before the
crash — a racoon2-in-netns XFRM/PF_KEY path bug in the initiator's SA install.
Grab the backtrace by running the initiator under gdb with the responder up
and add `-ex 'set environment RACOON2_ADMIN_SOCK /tmp/iked.sock-i2i'`; if the
plain run crashes, capture /proc/sys/kernel/core_pattern to a writable path
and gdb the core.  Likely a NULL deref from a bad PF_KEY/XFRM state in the
netns (initiator-side; unique to racoon2 as initiator, which the matrix had
never exercised).

Once the baseline (GETSPI / child install) is past, the ADDKE assertion is
the existing pattern: child rekey offers type-6 (both sa `esp_addke_alg
{ mlkem768; };`), the responder echoes type-6 + 16441, IKE_FOLLOWUP_KE
decaps, new SPI takes packets (ip xfrm state counters), no DELETE IKE_SA.

## Files
- initiator.conf / responder.conf — the two fqdn-identity PSK configs.
- bringup.sh — root bring-up; stops/restores production iked+spmd, kills
  stale i2i daemons, sets up netns+veth, both stacks, UDP-allow SPD, triggers
  `ikedctl -s /tmp/iked.sock-i2i establish-sa isakmp inet 192.0.2.2 192.0.2.1`.
