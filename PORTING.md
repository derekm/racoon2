# Porting the `int/gsoc2026` integration branch into upstream racoon2

Status guidance for the GSoC team taking over this work.

## Why a port map exists

`int/gsoc2026` does **not** share a merge-base with `origin/gsoc2026`
(it is a rebuilt history — roots differ, `git merge-base` returns nothing).
Do **not** try to `git merge` or `git rebase` the two histories, and do
**not** force-push `int/gsoc2026` onto `origin/gsoc2026`. Treat this branch
as the implementation trunk and bring in the upstream-only delta as a series
of reviewed commits **on top of this trunk**.

## New files here (port as-is, low conflict)

| File | What it is |
|------|-----------|
| `iked/ikev2_addke.c` | RFC 9370 ADDKE / ML-KEM round logic + helper TUs |
| `iked/ikev2_intermediate.c` | RFC 9242 SA-dispose/aux helpers (replay cache clear, IntAuth/ML-KEM state release) |
| `iked/ikev2_auth.c` | IKE_AUTH + RFC 9242 IntAuth_A appendix |
| `iked/ikev2_frag.c` | RFC 7383 fragmentation (send + reassemble) |
| `iked/ikev2_decrypt.c` | decrypt helpers (fragtest linkage) |
| `iked/ikev2_qcd.c` | RFC 6290 QCD maker |
| `iked/ikev2_resume_rec.c` | session-resume SR2R reader |
| `lib/if_xfrm.c` | XFRM backend (mostly new) |
| `samples/linux-matrix/` | netns PQC matrix (kinds, run.sh, cases.tsv) |
| `samples/systemd/` | iked/spmd unit set + drop-ins + hooks |
| `.github/workflows/integration.yml` | CI gate set |

## Hot files (highest conflict; port carefully, do not take upstream blind)

- `iked/ikev2.c` (~8.2k lines) — the ADDKE/intermediate negotiation, the
  initial IKE_SA type-6 offer + IKE_INTERMEDIATE round, IntAuth/AUTH, the
  lost-response recovery (cleartext outer msgid intercept + responder
  gen-0 replay + initiator fragment retransmit), R2 ordering, NAT-T float.
- `iked/ikev2_impl.h` — SA struct: intermediate/ADDKE/IntAuth fields,
  `intermediate_replay`/`intermediate_replay_msgid`, prev-gen key retention.
- `iked/isakmp.c` + `iked/isakmp_impl.h` — `isakmp_schedule_retransmit`
  helper, two-stage transmit (marker handled in `isakmp_transmit_noretry`).
- `lib/cfparse.y` / `lib/cftoken.l` / `lib/cfsetup.c` — grammar keywords
  (`offer_intermediate`, `addke_*`, `esp_addke_alg`, ML-KEM tokens).
- `iked/ike_conf.[ch]` — the `offer_intermediate` config key wiring.

Rule: after any port of a hot file, do not trust `make` exit 0 — delete the
untracked pre-generated `lib/cfparse.c` / `lib/cfparse.h` / `lib/cftoken.c`
so bison/flex regenerate, and prove a scratch config parses at runtime.

## Upstream-only delta to bring in (port as reviewed commits)

- PRs #32-36 on `origin/gsoc2026`: NAT-OA into PF_KEY (`xfrm-natt-oa`),
  IKEv1 address substitution, IKEv2 `IP_RW`, the second 4500 socket
  (`af96594` and parents). This tree has partial `IP_RW` handling and does
  not carry that series.

## Wire ground rules before exporting this branch as topics

1. RFC 3948 non-ESP marker must be present on **every** UDP/4500 send —
   normal, **fragmented** (SKF), and **retransmitted**. This was the
   highest-impact defect found in review (fragmented ML-KEM
   IKE_FOLLOWUP_KE to a NAT-T peer was unparseable).
2. The lost-intermediate-response recovery proves itself only when the
   `H1 replay` log marker fires under a loss that actually drops a response
   fragment (`samples/linux-matrix/kinds/i2iinit_drop.sh`, 80%→5% loss,
   bounded 4 retries, gate = `nreplay>=1`). A pass with no marker proves
   nothing.
3. Do **not** export `IKE_INTERMEDIATE` as a topic until: replay cache is
   cleared on AUTH-accept (done), the fragment/retransmit marker fix is in
   (done), and a deterministic 576-MTU fragment-aware kill test exists (TODO —
   the current test runs at veth MTU 1500).

## Vendor-parity roadmap (in order — do not start 8784 on the old carrier)

1. Finish wire correctness (marker on 4500; fragment-aware replay).
2. RFC 8784 PPK (mixed into SKEYSEED) — vendors shipped this first.
3. ADDKE rounds 2-7 as config (the transform table has 512/1024 already;
   the exchange currently hardcodes one round in `iked/ikev2.c`).
4. A strongSwan 6.0+ ML-KEM peer (distro charon often lacks ML-KEM; verify
   with `strings` on the charon binary before writing a row) — PQC rows must
   not stay racoon2↔racoon2 only.
5. EAP-MSCHAPv2 + certs (PSK-only cannot be the server the large vendors sell).
6. ML-DSA (after authentication).

Reference for "state of the art": PAN-OS 11.2+ ships 9242/9370 hybrid with up
to seven ADDKE rounds; Cisco ASA/FTD 9.18+ has 8784 and 9.19+ 9242/9370;
strongSwan 6.0 is the open-source ML-KEM IKEv2 reference.

## Docs that must stay current (status lies are defects)

`README.md`, `doc/addke-design.md`, `doc/macos-26-27-ikev2-client.md`,
`doc/int-gsoc2026.md`, `samples/linux-matrix/cases.tsv`. Any change that
moves a feature from "not implemented" to "implemented" (or changes a
proof target / marker) must update these in the same commit.
