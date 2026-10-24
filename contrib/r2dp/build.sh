#!/usr/bin/env bash
# r2dp build driver: dependencies, configure, build, test, milestone map.
# Usage: ./build.sh <command> [options]   (./build.sh help)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${BUILD_DIR:-$ROOT/build}"
DPDK_MIN="${DPDK_MIN:-23.11}"
MILESTONE="${MILESTONE:-0}"
RACOON2_SRC="${RACOON2_SRC:-}"
DRY_RUN=0
WITH_RACOON2_DEPS=0
WITH_TEST_DEPS=0

die()  { echo "error: $*" >&2; exit 1; }
info() { echo "==> $*"; }
warn() { echo "warn: $*" >&2; }
have() { command -v "$1" >/dev/null 2>&1; }
run()  { if [ "$DRY_RUN" = 1 ]; then echo "+ $*"; else "$@"; fi; }
vergte() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]; } # $1 >= $2

# ---------------------------------------------------------------- packages
# Milestone gate for each group:
#   core   M0+  compiler + meson/ninja
#   dpdk   M1+  DPDK LTS, numa, pyelftools (DPDK's own build needs it)
#   tests  M1+  netns/pcap tooling for the vdev e2e tests and XFRM oracle
#   r2     M0+  racoon2 build deps (only for the shim; --racoon2)
declare -A APT=(
  [core]="build-essential meson ninja-build pkg-config"
  [dpdk]="libdpdk-dev dpdk libnuma-dev python3-pyelftools libssl-dev"
  [tests]="iproute2 tcpdump python3-scapy"
  [r2]="autoconf automake libtool bison flex libssl-dev"
)
declare -A DNF=(
  [core]="gcc make meson ninja-build pkgconf-pkg-config"
  [dpdk]="dpdk-devel dpdk numactl-devel python3-pyelftools openssl-devel"
  [tests]="iproute tcpdump python3-scapy"
  [r2]="autoconf automake libtool bison flex openssl-devel"
)

pkg_groups() {
  local g="core"
  [ "$MILESTONE" -ge 1 ] && g="$g dpdk"
  [ "$WITH_TEST_DEPS" = 1 ] || [ "$MILESTONE" -ge 1 ] && g="$g tests"
  [ "$WITH_RACOON2_DEPS" = 1 ] && g="$g r2"
  echo "$g"
}

cmd_deps() {
  [ -r /etc/os-release ] || die "cannot detect distro (no /etc/os-release)"
  # shellcheck disable=SC1091
  . /etc/os-release
  local sudo="" pkgs="" g
  [ "$(id -u)" -ne 0 ] && have sudo && sudo="sudo"
  case "${ID:-} ${ID_LIKE:-}" in
    *debian*|*ubuntu*)
      for g in $(pkg_groups); do pkgs="$pkgs ${APT[$g]}"; done
      info "apt: $pkgs"
      run $sudo apt-get update
      run $sudo apt-get install -y $pkgs ;;
    *fedora*|*rhel*|*centos*)
      for g in $(pkg_groups); do pkgs="$pkgs ${DNF[$g]}"; done
      info "dnf: $pkgs"
      run $sudo dnf install -y $pkgs ;;
    *) die "unsupported distro '${ID:-?}': install deps manually (see 'check')" ;;
  esac
  if [ "$MILESTONE" -ge 1 ]; then
    info "distro DPDK may be older than $DPDK_MIN; 'check' will tell you."
    info "If so build an LTS from source: https://core.dpdk.org/download/"
  fi
}

# ------------------------------------------------------------------- check
cmd_check() {
  local fail=0
  need() { if have "$1"; then printf '  ok   %s\n' "$1"; else printf '  MISS %s  (%s)\n' "$1" "$2"; fail=1; fi; }
  info "milestone $MILESTONE requirements"
  have cc || have gcc || have clang || { echo "  MISS C compiler"; fail=1; }
  need meson "pip install meson / package meson"
  need ninja "package ninja-build"
  need pkg-config "package pkg-config"
  if have meson; then
    vergte "$(meson --version)" 0.57 && echo "  ok   meson $(meson --version) >= 0.57" \
      || { echo "  OLD  meson $(meson --version) < 0.57"; fail=1; }
  fi
  if [ "$MILESTONE" -ge 1 ]; then
    if have pkg-config && pkg-config --exists libdpdk; then
      local v; v="$(pkg-config --modversion libdpdk)"
      if vergte "$v" "$DPDK_MIN"; then echo "  ok   libdpdk $v >= $DPDK_MIN"
      else echo "  OLD  libdpdk $v < $DPDK_MIN"; fail=1; fi
    else
      echo "  MISS libdpdk (>= $DPDK_MIN); set PKG_CONFIG_PATH if built from source"; fail=1
    fi
    pkg-config --exists numa 2>/dev/null && echo "  ok   libnuma" \
      || { echo "  MISS libnuma"; fail=1; }
    need ip "package iproute2 (netns tests)"
    need tcpdump "package tcpdump"
    if [ -r /proc/meminfo ]; then
      local hp; hp="$(awk '/HugePages_Total/{print $2}' /proc/meminfo)"
      [ "${hp:-0}" -gt 0 ] && echo "  ok   hugepages: $hp" \
        || warn "no hugepages reserved; tests will use --no-huge, real runs need them"
    fi
  fi
  if [ -n "$RACOON2_SRC" ]; then
    [ -d "$RACOON2_SRC/lib" ] && echo "  ok   racoon2 src: $RACOON2_SRC" \
      || { echo "  MISS racoon2 src at $RACOON2_SRC"; fail=1; }
    for t in autoreconf bison flex; do need "$t" "racoon2 shim build"; done
  fi
  [ "$fail" = 0 ] && info "all requirements met" || { info "missing requirements (try: ./build.sh deps --milestone $MILESTONE)"; return 1; }
}

# ------------------------------------------------------- setup/build/test
cmd_setup() {
  have meson || die "meson not found (./build.sh deps)"
  local args=(-Dmilestone="$MILESTONE" -Ddpdk_min="$DPDK_MIN")
  [ -n "$RACOON2_SRC" ] && args+=(-Dracoon2_src="$RACOON2_SRC")
  if [ -f "$BUILD_DIR/build.ninja" ]; then
    info "reconfigure ($BUILD_DIR)"; run meson setup --reconfigure "$BUILD_DIR" "$ROOT" "${args[@]}"
  else
    info "configure ($BUILD_DIR)"; run meson setup "$BUILD_DIR" "$ROOT" "${args[@]}"
  fi
}
cmd_build() { cmd_setup; info "build"; run meson compile -C "$BUILD_DIR"; }
cmd_test()  { cmd_build; info "test"; run meson test -C "$BUILD_DIR" --print-errorlogs; }
cmd_clean() { info "rm -rf $BUILD_DIR"; rm -rf "$BUILD_DIR"; }
cmd_sanitize() { # M3 gate uses these; handy earlier too
  BUILD_DIR="$ROOT/build-asan"
  info "ASan+UBSan build ($BUILD_DIR)"
  local extra=(); [ -n "$RACOON2_SRC" ] && extra=(-Dracoon2_src="$RACOON2_SRC")
  run meson setup "$BUILD_DIR" "$ROOT" --wipe -Dmilestone="$MILESTONE" "${extra[@]}" -Db_sanitize=address,undefined -Db_lundef=false 2>/dev/null \
    || run meson setup "$BUILD_DIR" "$ROOT" -Dmilestone="$MILESTONE" "${extra[@]}" -Db_sanitize=address,undefined -Db_lundef=false
  run meson test -C "$BUILD_DIR" --print-errorlogs
}

cmd_e2e() { # clean clone -> patch -> build racoon2 -> two-peer IKEv2 over veth against mock forwarders
  [ -n "$RACOON2_SRC" ] || die "e2e needs --racoon2 PATH (a racoon2 git checkout)"
  local W="${E2E_WORK:-/tmp/r2dp-e2e-work}"
  info "install libr2dp + mockfwd -> $W/prefix"
  run meson setup --wipe "$W/mbuild" "$ROOT" --prefix="$W/prefix" -Dmilestone=0 >/dev/null 2>&1 \
    || run meson setup "$W/mbuild" "$ROOT" --prefix="$W/prefix" -Dmilestone=0 >/dev/null
  run meson install -C "$W/mbuild" >/dev/null
  info "build racoon2 with the r2dp backend"
  run "$ROOT/tests/e2e/build-racoon2.sh" "$RACOON2_SRC" "$W" "$W/prefix"
  info "IKEv2 end-to-end (needs root + iproute2)"
  run "$ROOT/tests/e2e/ike_e2e.sh" "$W/r2inst" "$W/prefix/bin/r2dp-mockfwd"
}

cmd_milestones() {
  local f="$ROOT/docs/MILESTONES.md"
  [ -r "$f" ] || die "missing $f"
  info "milestone map (details: docs/MILESTONES.md)"
  awk '/^## M[0-9]/{sub(/^## /,"");print "  " $0}' "$f"
  echo; echo "  current build target: M$MILESTONE  (--milestone N)"
}

usage() {
  cat <<EOF
r2dp build driver

Commands:
  deps         install system packages for the chosen milestone (apt/dnf)
  check        verify toolchain/DPDK/hugepages without installing
  setup        meson setup/reconfigure
  build        setup + compile
  test         build + run tests
  sanitize     ASan/UBSan build + tests
  e2e          (needs --racoon2 PATH, root) clean-clone racoon2 + patch + build, then IKEv2 over veth vs mock forwarders
  clean        remove build dir
  milestones   print the milestone map
  help         this text

Options:
  -m, --milestone N   highest milestone to build, 0-4 (default 0; M0 needs no DPDK)
      --racoon2 PATH  racoon2 checkout for shim build (adds its build deps)
      --test-deps     also install netns/pcap test tooling
      --dpdk-min VER  minimum DPDK version (default $DPDK_MIN)
  -n, --dry-run       print commands instead of running them
Env: BUILD_DIR, MILESTONE, DPDK_MIN, RACOON2_SRC
EOF
}

# --------------------------------------------------------------------- main
CMD="${1:-help}"; [ $# -gt 0 ] && shift
while [ $# -gt 0 ]; do
  case "$1" in
    -m|--milestone) MILESTONE="${2:?}"; shift 2 ;;
    --racoon2)      RACOON2_SRC="${2:?}"; WITH_RACOON2_DEPS=1; shift 2 ;;
    --test-deps)    WITH_TEST_DEPS=1; shift ;;
    --dpdk-min)     DPDK_MIN="${2:?}"; shift 2 ;;
    -n|--dry-run)   DRY_RUN=1; shift ;;
    -h|--help)      usage; exit 0 ;;
    *) die "unknown option: $1 (see help)" ;;
  esac
done
case "$MILESTONE" in 0|1|2|3|4) ;; *) die "milestone must be 0-4" ;; esac

case "$CMD" in
  deps) cmd_deps ;;       check) cmd_check ;;
  setup) cmd_setup ;;     build) cmd_build ;;
  test) cmd_test ;;       sanitize) cmd_sanitize ;;
  clean) cmd_clean ;;     milestones) cmd_milestones ;;
  e2e) cmd_e2e ;;
  help|-h|--help) usage ;;
  *) usage; die "unknown command: $CMD" ;;
esac
