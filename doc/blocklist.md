# iked + blocklistd

Off by default (`./configure --enable-blocklist`). Default tree links
without libblocklist: `iked/blocklist_peer.c` is stubs unless
`HAVE_BLOCKLIST` is set.

IKE is datagram. Use `blocklist_sa_r()` with the peer sockaddr **and
the iked UDP socket the datagram arrived on** (never `-1`, never
`blocklist()` on an accepted fd). blocklistd `getsockname()`s that fd
to match the `[local]` 500/4500 rule; libblocklist passes it with
`SCM_RIGHTS`, so `-1` makes `sendmsg()` fail with `EBADF` and the
report is lost (after 5 reconnect retries). Linux packet-filter half
is `derekm/blocklist` `linux-port` (nft sets + timeout).

## Call sites

| Event | Site | Action |
|-------|------|--------|
| packet shorter than ISAKMP header | `iked/isakmp.c` | AUTH_FAIL `iked shortpacket` |
| length field too small/large | `iked/isakmp.c` | AUTH_FAIL `iked malformed_len` |
| IKEv1 initiator cookie all-zero | `iked/ikev1/ikev1.c` | AUTH_FAIL `iked zero-cookie` |
| `ikev2_verify` VERIFIED_FAILURE (responder side) | `iked/ikev2_auth.c` | AUTH_FAIL `iked AUTH_FAILED` |
| `ikev2_verify` VERIFIED_SUCCESS (responder side) | `iked/ikev2_auth.c` | AUTH_OK `iked AUTH_OK` |

Init: `iked_blocklist_init()` from `main.c` after `isakmp_init()`.

Guards:

- AUTH_FAIL is rate-limited in iked: one report per source address per
  10 s (`IKED_BL_PEER_INTERVAL`) and at most 20 reports/s overall
  (`IKED_BL_GLOBAL_PER_SEC`). AUTH_OK is not rate-limited.
- AUTH results are only reported when iked is the **responder**; a
  gateway iked initiated to is never reported.
- On the NAT-T port, a "malformed" datagram without a non-ESP marker
  and >= 8 bytes is not reported (that is ESP leaking to userspace
  because `UDP_ENCAP_ESPINUDP` failed, i.e. a real client).
- IPv4-mapped IPv6 sources are reported as IPv4.
- `RACOON2_BLOCKLIST=off|log` in iked's environment disables reporting
  or logs "would report" lines without contacting blocklistd.

Not hooked: `INVALID_SYNTAX` on a live rekey (iOS), QCD replay,
window-mismatch, DPD silence. Those are protocol, not scanners.

blocklistd counts each AUTH_FAIL as 2 failures (`BL_ADD`), so
`nfail 8` bans after 4 reports.

Sample: `samples/blocklistd.conf.iked` (lists `udp` **and** `udp6`;
the family column is per-address-family).
Ubuntu CI job `build-blocklist` builds the lib from `linux-port`
(with `--runstatedir=/run/blocklistd` so the compiled-in socket path
matches `blocklistd.socket`) and compiles iked with
`--enable-blocklist`; it does not gate the live matrix.
