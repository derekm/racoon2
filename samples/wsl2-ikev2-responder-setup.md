# iOS / macOS IKEv2 road-warrior responder: live production setup

**Server-side counterpart of [doc/macos-26-27-ikev2-client.md](../doc/macos-26-27-ikev2-client.md).**
Describes the production deployment this config is running on, the
protocol fixes it depends on, and the one host-level gotcha that made
WiFi connects "slow" while LTE was instant.

Verified live: 2026-09-10 (iPhone IKEv2, LTE + WiFi, reconnect tests).

## Deployment layout

- Host: Windows 11, **WSL2 Ubuntu** with **mirrored networking**
  (`networkingMode=mirrored`). iked binds `192.168.68.79:500/4500`;
  the Windows host forwards UDP 500/4500 to the WSL IP.
- Built from this tree's `int/gsoc2026` branch, installed to
  `/usr/local/racoon2/`, run by systemd:
  `systemctl restart racoon2-iked` (spmd untouched; never SIGHUP —
  that runs `ikev2_shutdown()` and drops every SA).
- Config: `/usr/local/racoon2/etc/racoon2/macos_ikev2.conf` — this
  sample verbatim, minus the template lines. All values are
  environment substitutions set before iked starts
  (`MY_FQDN`, `PEERS_FQDN`, `IP_RW`, `MY_NET`, `PEERS_NET`,
  `MY_GWADDRESS`, `CP_ADDRPL4_START/END`, `PSKDIR`, `PRESHRD_KEY`).
- PSK: `$PSKDIR/$PRESHRD_KEY` shared-secret file (32 random bytes via
  `pskgen -r -s 32`). Client sheet: Remote ID `MY_FQDN`, Local ID
  `PEERS_FQDN`, Machine Auth = Shared Secret.
- Runtime state: resume dump `/var/lib/racoon2/resume` (saved at each
  connect; restores the IKE_SA at iked start so a reconnecting client
  completes in one RTT), QCD secret `/var/lib/racoon2/qcd.secret`.

## Cisco-style client sheet (iPhone Settings → VPN → IKEv2)

- Server: reachable IPv4 (port-forwarded host), Remote ID = `my_id`,
  Local ID = `peers_id`, User Auth None, Machine Auth Shared Secret.
- The client floats to UDP 4500 after NAT detection; `ip xfrm state`
  must then show `encap type espinudp` both directions.

## Protocol behavior this responder depends on (branch commits)

1. **DH choice follows the KEi in CREATE_CHILD_SA rekeys** (`bd64798`).
   Apple sends its child rekey with a single KEi in group 19 while its
   proposal list offers 14 and 19; a first-match responder selects 14,
   then rejects with INVALID_KE_PAYLOAD, and Apple DELETEs the whole
   IKE_SA ~24 min into the session. Selection must prefer the proposal
   whose DH equals the KEi group.
2. **INITIAL_CONTACT is honored** (`bd57e84`). On an authenticated
   INITIAL_CONTACT the responder flushes all other IKE_SAs with the
   same peer address. Without this, a resume-restored SA survives as a
   zombie pinned to a dead NAT-T port; its child rekey retransmits
   against a silent peer until `ikev2_abort` → SADB netlink ESRCH →
   **SIGSEGV** → systemd restart kills every live tunnel (observed
   07:03:31, fixed, never reproduced since).
3. **NAT-DETECTION notifies are echoed in INFORMATIONAL replies**
   (`7aa61ad`). iOS (`nwikev2`) re-validates its NAT binding ~10 min
   into a session by sending NAT_DETECTION_SOURCE_IP /
   NAT_DETECTION_DESTINATION_IP in an INFORMATIONAL on the
   established SA (RFC 7296 §2.23 semantics, normally IKE_SA_INIT).
   The established-state notify handler had no NAT-DETECTION case, so
   the reply was an empty `SK{}`; the peer treats that as "binding not
   confirmed" and silently deletes the SA ~4 min later (no DELETE
   message, no journal trace). Respond with `natt_create_natd`
   notifies — the same ones the IKE_SA_INIT reply carries.

Deploy with the standard upgrade path: `make install` +
`systemctl restart racoon2-iked` (spmd unchanged).

## WSL2 mirrored-network gotcha: the host-IP-on-lo alias

**Symptom:** WiFi connects retransmit IKE_SA_INIT for ~30 s and are
slow or never complete; LTE connects complete in <1 s. Same daemon,
same config, byte-identical replies on the wire — except the wire
shows *no reply at all* to the WiFi source IP.

**Cause:** WSL2 mirrored mode mirrors the Windows host's own public
IPv4 onto the guest's `lo` as a `/32` (`ip addr show lo` →
`inet 75.81.105.40/32 scope global lo`). An iPhone on WiFi hairpins
through the home router, so its packets arrive with that same public
IP as source. The guest kernel then treats the destination as local:
every reply iked sends to the client is routed into `lo` and never
reaches eth3. LTE clients carry the carrier-CGNAT IP (different), so
they route normally.

**Diagnosis (30 s):**

```sh
ip route get <client-public-ip>     # "local ... dev lo"  = broken
timeout 4 tcpdump -i eth3 -n -c1 'udp port 500' &   # probe:
(echo -n x >/dev/udp/<client-ip>/500)                # no packet on
wait                                                  # eth3 = swallowed
```

**Fix (persistent):** systemd oneshot `unmirror-lo.service` runs
`/usr/local/bin/unmirror-lo.sh` at boot, which deletes every `/32`
alias on `lo` except `127.*` and the WSL gateway marker
(`10.255.255.254/32`):

```sh
for a in $(ip -o addr show dev lo | awk '{print $4}'); do
    case "$a" in
    127.*|10.255.255.254/32|::1*) continue ;;
    */32) ip addr del "$a" dev lo 2>/dev/null ;;
    esac
done
```

After removal the route resolves via the gateway
(`via 192.168.68.1 dev eth3`) and the same probe appears on eth3.
Re-apply whenever the host's public IP changes (the mirror re-adds
the alias); the service is `RemainAfterExit=yes` but re-running the
script is idempotent.

## Verification cheatsheet

- Fast connect: journal shows INITIAL_CONTACT → SADB_ADD/UPDATE →
  QCD_TOKEN in the first second; client AUTH arrives <200 ms later.
- Tunnel healthy: `ip -s xfrm state | grep -A10 spi 0x...` shows the
  anti-replay seq climbing on both directions; `XfrmInError` and
  `XfrmInStateProtoError` stay 0.
- Reconnect after an interlude: the new session's INITIAL_CONTACT
  must log `flushed N stale IKE_SA(s)` (proves the zombie flush).
- Survives: a session must cross its first iOS NAT-DETECTION recheck
  (~10 min) and the ~50 min child rekey without any abort/DELETE.
- Read iked logs by the **embedded** timestamp inside each line
  (journald writes batches late; `--since` on the journal time is
  misleading). `sort` on the embedded `Sep dd hh:mm:ss` field.
