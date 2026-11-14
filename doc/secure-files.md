# File and directory safety checks (ENABLE_SECURE)

`--enable-secure` is the configure default, so `rc_safefile()` and
`rc_privatedir()` (lib/safefile.c) are live in every default build since
SF-01 (8fe9880).  Before that commit the define never reached the
compiler and both functions returned 0 unconditionally.  This note
records what is now rejected and the decision taken for each follow-up
item of the safefile work order (SF-02..SF-05).

## What is rejected (deploy checklist)

| Object | Check | Result code |
|---|---|---|
| any checked file/dir | process is setuid (euid != uid) | 1 SETUID |
| any checked file/dir | `stat(2)` fails (missing, EACCES, ...) | -1 ERRNO |
| any checked file/dir | owner is not the running (real) uid | 2 OWNER |
| file | not a regular file (after following symlinks) | 3 NOTREG |
| secret file (PSK, private key) | any group or other permission bit | 5 PERMISSION |
| non-secret file (certificate, peer public key, CA) | world-writable (o+w) | 5 PERMISSION |
| spmd/iked socket directory (`rc_privatedir`, parent of the spmif socket) | not a directory, or any group/other bit | 4 NOTDIR / 5 PERMISSION |

Path classes that worked before 8fe9880 and are refused now:

- a socket path directly in a shared directory such as `/tmp` or `/var/tmp`
  (1777, root-owned): use a private 0700 directory owned by the daemon's
  uid, e.g. `/run/racoon2` created by the service manager
  (`RuntimeDirectory=racoon2`, `RuntimeDirectoryMode=0700`);
- configuration, certificate or key files owned by another uid than the
  one the daemon runs as (e.g. files owned by an admin user while the
  daemon runs as root);
- PSK / private-key files with any group or other bit (e.g. 0640 root:racoon);
- certificate / public-key files that are world-writable.

Pre-deploy check on a host (read-only; adjust the paths to the host's
config):

    find /etc/racoon2 -xdev \( -perm -0002 -o ! -user root \) -ls
    find /etc/racoon2 -xdev -type f \( -name '*.psk' -o -name '*key*' \) -perm /0077 -ls
    stat -c '%a %U %n' "$(dirname "$(awk '/spmd_interface/,/}/' /etc/racoon2/racoon2.conf | sed -n 's/.*unix *"\([^"]*\)".*/\1/p' | head -1)")"

Any line printed by the first two commands is a file iked will refuse;
the third must print `700 <daemon user>`.

## Decisions on SF-02..SF-05

- **SF-02 (non-secret integrity): fixed.**  Non-secret files are trust
  inputs (peer certificates, raw public keys, CA files), so integrity
  matters even though secrecy does not.  World write is now refused.
  Group write stays accepted because shared admin groups are a supported
  deployment and the owner check already pins the file to the daemon's
  uid.  Tests: `lib/safefile_test` (0644/0664 accepted, 0666/0602
  rejected for sec=0, 0666 rejected for sec=1).
- **SF-03 (checked object vs consumed object): documented, not changed.**
  Both helpers `stat(2)` the path and follow symlinks on purpose
  (packaged configs commonly symlink certificates); callers then open by
  path (OpenSSL `BIO_new_file`, `fopen`).  Binding the check to the opened
  descriptor needs an fd-based load path through the crypto layer and is
  a separate design change.  The residual window requires write access to
  a directory on the path, which the owner/mode checks on the files do not
  cover; keep `/etc/racoon2` and its parents root-owned and not
  group/other-writable.
- **SF-04 (identity/directory rules): policy as implemented.**  Owner must
  equal the real uid, setuid execution is refused, and private
  directories must be 0700 owned by that uid.  No group or ACL allowlist.
  The checks run at configuration load, after privilege changes the
  daemon makes (none in tree: iked/spmd run as the uid they are started
  with).  The test harness and CI now create private 0700 socket
  directories (20280d9) instead of relaxing the rule.
- **SF-05 (errno): verified, plus one diagnostic fix.**  `RC_SAFEFILE_ERRNO`
  formats the ambient errno.  Every in-tree caller formats immediately
  after `rc_safefile()` with no intervening call, so the reported errno is
  the `stat(2)` one; the pre_shared_key load path did not print it at all
  and now does.  The message table matches `enum` codes 0..5 and keeps its
  out-of-range guard; `lib/safefile_test` checks the ENOENT path, codes 4/5,
  and out-of-range/negative values.
