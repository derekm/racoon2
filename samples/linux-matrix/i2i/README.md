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

### Current lead: fragmented IKE_FOLLOWUP_KE reassembly (chunk/padding boundary)

pcap measurement (capture-followup.sh / capture-key.sh) — established keyless +
with keys:
- The initiator sends **3** well-formed SKF fragments (1/3 2/3 3/3, msgid=2,
  payload_len 536/536/264, recovered inner KE=0x22), NOT a lost-fragment bug.
- They carry the **same ISPI/RSIPI as the IKE_AUTH** (ae44c6cc.../c374a296...), so
  same IKE_SA.
- `sk_e_i` (32B, AES-256-CBC) dumped live via gdb and **validated**: the IKE_AUTH
  SK decrypts perfectly to `macos.client` IDi + valid PKCS7 pad.  The fragment
  frames do NOT decode with sk_e_i or sk_e_r under any iv/icv framing (CBC, icv
  16/32, iv shift 0..39) — yet frag_recv's own decrypt path demonstrably succeeds
  (it reaches reassembly + check_payloads).  So a one-byte framing difference
  between the SK (IKE_AUTH) and SKF (fragment) layouts is the wedge: frag_send
  builds `skf+encrypted+icv` with `encrypted = iv+ct` (496B), and only the
  responder's own handling of that exact framing is correct.
- The responder then reassembles and `ikev2_check_payloads(packet, TRUE)` fails
  ("malformed payload format") -> the merged inner chain is byte-corrupt.

Definitive next measurement (no source change): gdb-break `ikev2_frag_recv` on
the responder and dump its own `decrypted` vchar per fragment (the actual bytes
frag_recv strips + merges), plus the reassembled `full_pkt`.  That removes all
offline framing guesswork and pins the exact ±N byte error, then the child XFRM
install (ikev2_child_addke_install) lands.

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
