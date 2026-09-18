# iked<->iked netns ADDKE matrix — bring-up harness (Fedora, wip)

Goal: continuously verify racoon2 PQC ADDKE end-to-end WITHOUT a phone or a
charon that has ML-KEM (neither WSL 5.9.13 nor Fedora RPM strongSwan 6.0.7
exposes mlkem768; only other WITH_ADDKE racoon2 can offer/select type-6).
So the initiator is itself a racoon2, running in the netns, offering
esp_addke_alg; the responder is a passive racoon2 in the host namespace.

## Status (2026-09-18): ISOLATED matrix up; IKE_SA ESTABLISHED w/ ADDKE; followup-reassembly is the current lead

**The matrix is now fully isolated from production** (`bringup-isolated.sh`):
- Both test peers run in their OWN netns on a P2P veth (initiator `192.0.2.2`,
  responder `192.0.2.1`).  Each netns is a separate socket + XFRM stack, so the
  matrix NEVER stops production iked/spmd, never binds host 500/4500, never
  mutates host `ip xfrm`.  Verified: production iked+spmd stay `active` before
  and after every run.
- **Private resume dir per run** (`RACOON2_RESUME_DIR=/tmp/r2i2i-resume`, new
  env override mirroring `RACOON2_ADMIN_SOCK`): test dump state can never
  overlap production's `/var/lib/racoon2/resume` (a stale shared dump made a
  test responder skip a fresh child with "pending ADDKE followup; skipped,
  will rekey").  Verified: test dumps land in /tmp/r2i2i-resume, production
  resume dir untouched.
- Stale `/tmp/spmif-*` + `iked.sock-*` purged each run (a dead listener made
  `-S` pass and the next iked die `SPMIF: Connection refused`).

Real code fixes landed (all on `int/gsoc2026`):
- `ee01010` responder: an ADDKE (type-6) child negotiated on the INITIAL IKE_AUTH
  child was answered with a bare CREATE_CHILD_SA response missing IDr+AUTH (RFC
  7296 violation) -> initiator aborted "message lacks IDr".  `ikev2_responder_
  state1_send` is now used for a `RES_IKE_AUTH_RCVD` addke child; a genuine rekey
  (`ESTABLISHED`) still gets the child-only form.  IKE_SA now reaches ESTABLISHED.
- `aa9faa5` initiator: `ikev2_initiator_followup_send` double-freed the
  transmit-owned pkt.  gdb backtrace: `rc_vfree:436 <- followup_send <-
  update_child:2644` — `ikev2_transmit` owns/frees pkt, so the manual free was a
  double-free (`free(): invalid pointer`).  Removed it.
- Earlier: `f23b468` RACOON2_RESUME_DIR; `75de6ee` GETSPI seq; `b246678` OOM
  NULL-deref; `c4a32d4` RACOON2_ADMIN_SOCK; `71a6a5b` sadb_poll memset.

Live state: both sides reach IKE_SA **ESTABLISHED** with type-6 (mlkem768) on
the initial child, then both arm the ADDKE followup timeout (~10s) which expires:
the initiator's ~1200-byte IKE_FOLLOWUP_KE (KEi = 4 + 1184-byte ML-KEM-768 pub,
+ 16-byte ADDKE link) is **always fragmented** — RFC 7383 fragmentation is
unconditional here — sent as 2 × ~564 B datagrams, and the receiver never
completes the fragmented-followup REASSEMBLY, so no KEr comes back.

### SOLVED: fragmented-followup corruption was a key-direction bug in frag_send

Root-caused with pcap + live gdb (no source instrumentation at first):
`ikev2_frag_send()` re-extracted its OWN just-encrypted message's inner payloads
by calling `ikev2_decrypt()`, which decrypts with the RECEIVE-direction key
(`is_initiator ? sk_e_r : sk_e_i`).  The initiator encrypted with sk_e_i, so it
"decrypted" with sk_e_r -> garbage inner payloads, and every SKF fragment
carried garbage.  The receiver decrypted them correctly (valid per-fragment
pads, byte-identical to the initiator's garbage inner) -> check_payloads()
"malformed payload format", followup never processed.

Fix (`00d671d`): refactored ikev2_decrypt into an internal core with a
key-direction flag; receive path keeps `ikev2_decrypt()`, and fragmentation
now uses the new `ikev2_decrypt_local()` (SEND-direction key).  Verified live:
the followup now parses and reaches ikev2_followup_ke_recv on both sides (no
more malformed-payload).

### Current lead: ADDKE link matching on the mutated fragmented followup

With the corruption fixed, the exchange reaches the RFC 9370 ADDKE state
machine, which now shows the next distinct blocker:
- responder `ikev2_followup_ke_recv: no pending ADDKE state for link` — its
  pending ADDKE child's `addke_link` does not match the link the initiator sent
  (initiator picks its own random 16-byte link; the two sides must agree for
  followup_ke_find_child to map the followup to the child);
- initiator `IKE_FOLLOWUP_KE response missing KE` + `not advancing (fragmented
  path)`.

Next focused pass: reconcile the ADDKE link between initiator and responder
(RFC 9370 link semantics on the initial-child followup), then the child XFRM
install (ikev2_child_addke_install) lands and the ADDKE assertion is green.

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
