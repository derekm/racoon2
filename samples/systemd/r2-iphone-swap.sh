#!/bin/bash
#	r2-iphone-swap.sh — swap HEAD iked/spmd/libracoon onto the live Fedora box
#
#	Repo copy (samples/systemd/r2-iphone-swap.sh) is authoritative. Ship it
#	to the box before use:
#	    scp samples/systemd/r2-iphone-swap.sh yescorp@192.168.0.165:~
#	Run as yescorp; every privileged step is `sudo -n` (passwordless).
#
#	Stage layout (built earlier, never clobbers prod):
#	    /tmp/r2-iphone-b/...                  build source (unpack)
#	    /tmp/r2-iphone-stage/usr/local/racoon2/{sbin,lib}   DESTDIR install
#
#	Provenance: the stage is stamped by `echo <commit|tree> >
#	$STAGE/<PREFIX-relative>/.r2-build-commit` at build/archive time. This
#	script reads that stamp (falling back to `git -C /tmp/r2-iphone-b` if the
#	build source is a checkout), records it in the deploy manifest, and aborts
#	on a mismatch with `--expect <id>`. Unstamped stages warn but proceed.
#
#	HAZARDS THIS SCRIPT PREVENTS (all seen in production):
#	* systemd `stop` is async: after `systemctl stop`, daemons can still hold
#	  the binaries (`Text file busy`) or `Requires=spmd.service` can pull spmd
#	  back up. We stop, sleep, and require an EMPTY pgrep before copying.
#	* The linker resolves the ELF SONAME `libracoon.so.0`, not
#	  `libracoon.so.0.0.0`. A swap that copies the .so.0.0.0 but leaves
#	  `libracoon.so.0 -> libracoon.so.0.0.0.bak-*` silently loads the OLD lib
#	  -> new iked died `unsupported kmp_auth_method (PresharedKey)` and spmd
#	  login returned `550 FAILED(Internal Error)` (enum/ABI mismatch, NOT a
#	  code regression). We pin BOTH symlinks after copying.
#	* Stale `libracoon.so.0.0.0.bak-*` copies accumulate in the live lib dir
#	  and are exactly the bait for the symlink trap above. They are moved to
#	  $BKUP_DIR (outside the loader path) before the swap.
#
#	Proof output: installed==staged sha256 for all three artifacts, daemon
#	active+pids, :500/:4500 bound, and a /proc map check that the RUNNING
#	daemons actually loaded the new lib (not the old one via a stale link).

set -u

STAGE=/tmp/r2-iphone-stage/usr/local/racoon2
L=/usr/local/racoon2
MYDIR="$(cd "$(dirname "$0")" && pwd)"
BKUP_DIR="$L/lib/.lib-backups"
MANIFEST="$L/.r2-deploy-manifest"

EXPECT=""
while [ $# -gt 0 ]; do
	case "$1" in
		--expect) EXPECT="${2:-}"; shift 2 ;;
		*) echo "usage: $0 [--expect <commit-or-tree>]" >&2; exit 2 ;;
	esac
done

if [ ! -x "$STAGE/sbin/iked" ] || [ ! -x "$STAGE/sbin/spmd" ]; then
	echo "FATAL: staged binaries missing under $STAGE" >&2
	exit 1
fi

# ---- provenance -----------------------------------------------------------
PROV_ID=""
if [ -f "$STAGE/.r2-build-commit" ]; then
	PROV_ID="$(cat "$STAGE/.r2-build-commit")"
elif [ -d /tmp/r2-iphone-b/.git ]; then
	PROV_ID="$(git -C /tmp/r2-iphone-b rev-parse HEAD 2>/dev/null)"
fi
if [ -n "$PROV_ID" ]; then
	echo "build provenance: $PROV_ID"
	if [ -n "$EXPECT" ] && [ "$PROV_ID" != "$EXPECT" ]; then
		echo "FATAL: stage provenance $PROV_ID != expected $EXPECT" >&2
		exit 1
	fi
else
	echo "WARN: stage is NOT provenance-stamped (no .r2-build-commit, no git)"
	if [ -n "$EXPECT" ]; then
		echo "  and --expect $EXPECT cannot be verified — aborting" >&2
		exit 1
	fi
fi

# ---- stop + confirm quiet --------------------------------------------------
sudo -n systemctl stop iked spmd 2>/dev/null
sleep 2
if pgrep -af "racoon2/sbin/(iked|spmd)" | grep -vE "bash -c|pgrep" >/dev/null; then
	echo "FATAL: daemons still running after stop; kill strays first" >&2
	exit 1
fi
echo "no daemons running"

# ---- prune stale backup libs out of the loader path ------------------------
if ls "$L"/lib/libracoon.so.0.0.0.bak-* >/dev/null 2>&1; then
	sudo -n mkdir -p "$BKUP_DIR"
	sudo -n mv "$L"/lib/libracoon.so.0.0.0.bak-* "$BKUP_DIR"/
	echo "moved stale lib backups -> $BKUP_DIR"
fi

# ---- swap binaries + lib ---------------------------------------------------
sudo -n cp -p "$STAGE/sbin/iked" "$L/sbin/iked"
sudo -n cp -p "$STAGE/sbin/spmd" "$L/sbin/spmd"
sudo -n cp -p "$STAGE/lib/libracoon.so.0.0.0" "$L/lib/libracoon.so.0.0.0"
# Pin BOTH unversioned symlinks to the new lib (see HAZARDS above).
sudo -n ln -sf libracoon.so.0.0.0 "$L/lib/libracoon.so.0"
sudo -n ln -sf libracoon.so.0.0.0 "$L/lib/libracoon.so"
echo "libracoon.so* after swap:"
ls -la "$L"/lib/libracoon.so*
echo COPY_OK

# ---- start ----------------------------------------------------------------
sudo -n systemctl start spmd
sudo -n systemctl start iked
sleep 3

# ---- proof: installed == staged --------------------------------------------
echo "--- PROOF hashes (uniq count 1 = installed==staged) ---"
sha256sum "$L/sbin/iked" "$STAGE/sbin/iked" | awk '{print $1}' | uniq -c
sha256sum "$L/sbin/spmd" "$STAGE/sbin/spmd" | awk '{print $1}' | uniq -c
sha256sum "$L/lib/libracoon.so.0.0.0" "$STAGE/lib/libracoon.so.0.0.0" | awk '{print $1}' | uniq -c
echo "--- active + pids ---"
systemctl is-active iked spmd
pgrep -af "racoon2/sbin/(iked|spmd)" | grep -vE "bash -c|pgrep"
echo "--- ports ---"
ss -lunp | grep -E ":500|:4500"
echo "--- running daemons mapped lib (must be /usr/local/racoon2/lib/libracoon.so.0.0.0) ---"
for p in $(pgrep -x iked; pgrep -x spmd); do
	M="$(sudo -n grep -m1 'racoon2/lib/libracoon.so.0.0.0' "/proc/$p/maps" 2>/dev/null)"
	# strip leading addresses/perms for a readable line
	M="${M##* }"
	echo "pid $p: ${M:-MISSING (old lib mapped?)}"
done

# ---- deploy manifest --------------------------------------------------------
{
	echo "time:            $(date -Is)"
	echo "provenance:      ${PROV_ID:-UNSTAMPED}"
	[ -n "$EXPECT" ] && echo "expected:        $EXPECT"
	echo "iked sha256:     $(sha256sum "$L/sbin/iked" | awk '{print $1}')"
	echo "spmd sha256:     $(sha256sum "$L/sbin/spmd" | awk '{print $1}')"
	echo "libracoon sha256: $(sha256sum "$L/lib/libracoon.so.0.0.0" | awk '{print $1}')"
	echo "sbin/iked ->     $(readlink -f "$L/sbin/iked")"
	echo "libracoon.so.0 -> $L/lib/$(readlink "$L/lib/libracoon.so.0")"
	echo "libracoon.so   -> $L/lib/$(readlink "$L/lib/libracoon.so")"
	echo "iked pid:        $(pgrep -x iked | tr '\n' ' ')"
	echo "spmd pid:        $(pgrep -x spmd | tr '\n' ' ')"
} | sudo -n tee "$MANIFEST" >/dev/null
echo "manifest written -> $MANIFEST"
