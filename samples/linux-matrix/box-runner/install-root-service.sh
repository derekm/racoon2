#!/usr/bin/bash
set -Eeuo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run this installer as root (for example: sudo ./install-root-service.sh)." >&2
  exit 1
fi
if ! getent passwd github >/dev/null; then
  echo "The dedicated github runner account must exist first." >&2
  exit 1
fi
if id -nG github | tr ' ' '\n' | grep -qxE 'wheel|sudo'; then
  echo "Refusing to install: github must not belong to wheel or sudo." >&2
  exit 1
fi

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
install -o root -g root -m 0755 "$here/racoon2-box-test" /usr/local/sbin/racoon2-box-test
install -o root -g root -m 0644 "$here/racoon2-box-test@.service" /etc/systemd/system/racoon2-box-test@.service
install -o root -g root -m 0644 "$here/50-racoon2-box-test.rules" /etc/polkit-1/rules.d/50-racoon2-box-test.rules
install -d -o root -g github -m 2750 /var/lib/racoon2-box-test /var/lib/racoon2-box-test/runs

if command -v restorecon >/dev/null 2>&1; then
  restorecon -RF /usr/local/sbin/racoon2-box-test /etc/systemd/system/racoon2-box-test@.service /etc/polkit-1/rules.d/50-racoon2-box-test.rules /var/lib/racoon2-box-test
fi
systemd-analyze verify /etc/systemd/system/racoon2-box-test@.service
systemctl daemon-reload
printf 'Installed the root-owned test service and scoped Polkit rule.\n'
printf 'Runner account groups: '; id -nG github
printf 'The workflow only runs on int/gsoc2026 via schedule or manual dispatch; no PR trigger is configured.\n'
