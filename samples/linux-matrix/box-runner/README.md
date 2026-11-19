# Box runner (Fedora/Linux)

This directory contains the root-owned wrapper used by the `box-evidence.yml`
GitHub Actions workflow. The GitHub runner itself runs as the dedicated `github`
account, which must not be in `wheel`/`sudo` and must not have a sudoers grant.

## Security boundary

The repository is public. The workflow intentionally has only `schedule` and
`workflow_dispatch` triggers, is restricted to `int/gsoc2026`, and has no
`pull_request` trigger. The unprivileged runner may start only
`racoon2-box-test@<sha>-<run-id>-<attempt>.service` through Polkit. The root-owned
wrapper re-fetches the public branch and refuses to run unless the requested
SHA is exactly its current tip. It builds under `/var/lib/racoon2-box-test`
using `DESTDIR`, so it does not install binaries or systemd units into the host.
The current DPD test still runs as root because it creates network namespaces
and starts the daemons. Therefore, any code merged to the trusted branch is
executed by that root test service; fork PR code is never dispatched there.

## Install the root service

On the Fedora box, ensure the `github` user exists and has no sudo privileges,
then copy this repository checkout to the box and run:

```bash
sudo bash samples/linux-matrix/box-runner/install-root-service.sh
```

The host needs `git`, `autoconf`, `automake`, `libtool`, `pkgconf-pkg-config`,
`gcc`, `make`, `openssl-devel`, `libpcap-devel`, `krb5-devel`, `bison`, `flex`,
`iproute`, `tcpdump`, `procps-ng`, and `iputils`. Fedora 45 also needs
`openssl3-libs` for the GitHub runner's supported OpenSSL ABI alongside the
host's OpenSSL 4 libraries. Install packages as an administrator; the runner
account does not install packages or elevate itself.

The runner registration and service are managed separately using GitHub's
repository runner settings. Register a runner with the labels
`self-hosted,linux,x64,racoon2-box`, and run its service as `github`.

## Run and inspect

The workflow runs nightly and can be started manually on `int/gsoc2026`. It
runs only the `i2ike-silence` DPD gate, requires a non-empty live result, and
uploads the runner log, structured TSV, exit code, and captured row/daemon logs
as an artifact. Test files are placed under
`/var/lib/racoon2-box-test/runs/<sha>/<run-id>-<attempt>/`, so a failed service
start cannot cause an earlier run's files to be uploaded. The root service
stages project files and test artifacts there for the unprivileged runner to read.
