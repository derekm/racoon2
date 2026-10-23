# OPERATIONS — racoon2 runbook

Durable operational warnings distilled from the `int/gsoc2026` developer
journal (`doc/int-gsoc2026.md`). These are run-time/install practices for
live and verification builds. Design notes and dated session evidence live in
the journal; this file keeps only the rules that stay true.

## (a) Production deploy rules

- The only documented install path is the top-level `make install` after
  `./configure && make`. It recurses through `SUBDIRS = lib spmd kinkd iked
  ...`, so `libracoon` is always installed before `iked`.
- Stock production build config: `--enable-pcap --enable-debug
  --enable-addke` only. Install to the canonical prefix `/usr/local/racoon2`.
- Never do a one-off build into `/tmp/r2prod` (or any scratch prefix) and call
  it the live install.
- Never hand-edit systemd unit files for iked (the unit is `iked.service`,
  not `racoon2-iked`). After any unit-file change, run
  `systemctl daemon-reload`.
- Use a separate, dedicated prefix for matrix/verification builds —
  `/usr/local/racoon2-i2i` — so build/test activity never races the live
  prefix.
- Only a coordinated production deploy touches the live
  `/usr/local/racoon2` prefix. Do not push test or experimental binaries
  into it as a side effect of a matrix run.
- Restart the service after install: `systemctl restart iked`.
- Verify the running binary actually has the change (verify by running, not
  by assumption): `md5sum /usr/local/racoon2/lib/libracoon.so.0.0.0
  /mnt/.../racoon2/lib/.libs/libracoon.so.0.0.0` must match (same check for
  `sbin/iked` vs `iked/.libs/iked`).
- After copying `libracoon.so`, the `.../libracoon.so.0` symlink must point
  at the new real library (`ln -sf libracoon.so.0.0.0 .../libracoon.so.0`). A
  stale `.so.0` symlink makes the new iked die with
  `unsupported kmp_auth_method (PresharedKey)` and spmd login `550` — an
  enum/ABI mismatch, not a code regression.
- Any recorded deploy commit is a dated snapshot; do not treat a historical
  HEAD as current.

## (b) Build / install-order traps

- Per-directory installs are off the documented path. `make -C iked install`
  alone leaves a stale `/usr/local/racoon2/lib/libracoon.so` behind and the
  new iked silently links the old library at runtime (duplicate journal lines
  until the lib was reinstalled). If a per-dir install is ever done, `lib`
  must go first: `make -C lib install && make -C iked install`.
- After any `configure.ac` change, regenerate the build configuration
  (`autoreconf` / reconfigure) before rebuilding — otherwise `make` can link
  against stale artifacts.
- Even after a rebuild, confirm the dynamic dependency actually resolved to
  the new library with `nm -D` on the installed `.so`/binary; don't assume the
  link picked up what you think it did.
- On a Windows checkout, watch for CRLF line endings — they can corrupt
  configure scripts, Makefiles, and unit/script files. Keep the working
  files LF.
- `systemctl daemon-reload` is required after any unit-file change so
  `systemctl restart iked` uses the edited unit.

## (c) Secret handling

- The PSK is a verbatim secret file: store the pre-shared key content exactly
  as 32 bytes, file mode `0600`, owner `root:root`, parent directory `0700`.
- Never base64-decode or otherwise transform the PSK — the bytes are used
  verbatim.
- Never paste the PSK (or any secret) into logs, chat, or reports.
- `radius_secret_file` (the RADIUS shared secret) is read inside the process;
  never pass it on the command line where it would be visible in `ps`
  output/argv.

## (d) Live-production safety

- Never run the linux-matrix netns IKE rows (workers=0) against a live phone
  session. Matrix rows are for isolated namespaces / CI, not the live peer.
- Restarting iked drops the tunnel even if it resumes the IKE_SA; do not
  bounce a live iked that currently holds a phone session unless explicitly
  asked.
- Do not `pkill` the systemd-managed iked. Kill iked only within its own
  scope (a scoped, targeted `kill`, e.g. `kill -C`/targeted to the exact
  unit or PID), never a broad pattern kill that could take down unrelated
  processes.
- Verify by running, never by mocks: after any deploy, confirm the exact
  running binary/library is the one you built (md5sum) before treating the
  change as live.
- Do not claim host reboot or RFC 5723 "resume" works until it has actually
  been measured.
- Do not xxd resume dumps past magic/cookies.
- Do not ping the CP inner address from WSL.

## (e) Phone / iOS soak expectations

- A DPD silence-then-err=110 pattern is peer/transport silence (no DELETE, no
  CREATE_CHILD on the wire), not a DPD patch symptom. Don't read it as a
  racoon2 DPD defect; it reflects the remote closing down silently.
- Child rekeys and IKE_SA rekeys have different cadences/shapes from iOS:
  IKE_SA rekeys are ~3600s hard cycle plus an iOS-initiated ~1440s cadence,
  and spawned as IKE_SA rekey + ESP rekey pairs. Child rekey cadence is set by
  `ikev2_child_rekey_floor` (default 0 / off so iOS can initiate ~1440s).
  Read logs per-shape, not as one uniform "rekey".
- MOBIKE (RFC 4555) is negotiated/supported, but the address may never
  actually move — a negotiated MOBIKE (and MOBIKE_SUPPORTED notify) is not
  proof a network transition occurred.

---
*Distilled from `doc/int-gsoc2026.md`. See that file for provenance and the
dated evidence behind each rule.*

## == Out-of-date in int-gsoc2026.md (do not keep) ==

Claims in the journal that are contradicted by later entries in the same
file. Keep these out of any runbook:

- "strongSwan charon U5.9.13 (ML-KEM-capable) present" (WSL, 2026-09-18) —
  contradicted later by "WSL charon 5.9.13 still has no ML-KEM".
- "Fedora ... no strongSwan/charon — install it" (2026-09-18) — superseded by
  the 2026-09-26 proof that Fedora strongSwan 6.0.7 ships the `ml` plugin and
  `i2iinit-charon` is box-green.
- "live on Fedora (NRestarts=0)" (2026-09-18 ADDKE landing) — a dated
  snapshot, not a permanent invariant; later documented production deploys
  (PPK fixes 2026-09-28) necessarily restarted the daemon.
