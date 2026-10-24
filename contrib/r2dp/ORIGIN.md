# Provenance

Landed from Mark Wilcox's `r2dp-claude.zip` (Telegram, 2026-10-24).

The zip had **no git history** (no `.git`, no commits to preserve).
This tree is that snapshot plus the racoon2 backend patch applied to
`int/gsoc2026` (patch was pinned to `2fd758a`; it applied clean).

**In the zip:** proto.h, mockfwd.c, if_r2dp.c, the racoon2 configure
patch, build.sh, ike_e2e.sh, README, MILESTONES.

**Claimed by the README but absent from the zip:** `include/r2dp/client.h`,
`libr2dp/`, `tests/` (empty dirs only). A `--with-km-backend=r2dp` build
still needs an installed libr2dp for `r2dp/client.h` and `-lr2dp`.
