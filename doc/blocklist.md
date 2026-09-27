# iked + blocklistd

Off by default (`./configure --enable-blocklist`). Default tree links
without libblocklist: `iked/blocklist_peer.c` is stubs unless
`HAVE_BLOCKLIST` is set.

IKE is datagram. Use `blocklist_sa_r()` with the peer sockaddr, never
`blocklist()` on an accepted fd. Linux packet-filter half is
`derekm/blocklist` `linux-port` (nft sets + timeout).

## Call sites

| Event | Site | Action |
|-------|------|--------|
| packet shorter than ISAKMP header | `iked/isakmp.c` | AUTH_FAIL `iked shortpacket` |
| length field too small/large | `iked/isakmp.c` | AUTH_FAIL `iked malformed_len` |
| IKEv1 initiator cookie all-zero | `iked/ikev1/ikev1.c` | AUTH_FAIL `iked zero-cookie` |
| `ikev2_verify` VERIFIED_FAILURE | `iked/ikev2_auth.c` | AUTH_FAIL `iked AUTH_FAILED` |
| `ikev2_verify` VERIFIED_SUCCESS | `iked/ikev2_auth.c` | AUTH_OK `iked AUTH_OK` |

Init: `iked_blocklist_init()` from `main.c` after `isakmp_init()`.

Not hooked: `INVALID_SYNTAX` on a live rekey (iOS), QCD replay,
window-mismatch, DPD silence. Those are protocol, not scanners.

Sample: `samples/blocklistd.conf.iked`.
Ubuntu CI job `build-blocklist` builds the lib from `linux-port` and
compiles iked with `--enable-blocklist`; it does not gate the live matrix.
