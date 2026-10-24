# Road-warrior sample pack

These are three gateway configs you can copy and paste, one per client
authentication method. All three use the same tunnel shape: clients get an
inner address from `rw_pool` (10.99.0.10-250) and reach `10.10.0.0/16` behind
the gateway. `make check` runs `iked -C` on each file
(`iked/rwsamplecheck.sh`), so they always parse with the tree they ship in.

| File | Client authenticates with | Gateway authenticates with | Extra pieces |
|---|---|---|---|
| `psk.conf` | pre-shared key | the same PSK | `psk/rw.psk` (0600) |
| `cert.conf` | X.509 certificate signed by `ca.crt` | `gw.crt` / `gw.key` | a CA; one client cert per device |
| `eap-mschapv2.conf` | EAP-MSCHAPv2 user name and password (checked by RADIUS) | `gw.crt` / `gw.key` | a RADIUS server, e.g. FreeRADIUS with `default_eap_type = mschapv2` |

> **EAP-MSCHAPv2 caveat:** MSCHAPv2 is a weak password method. It is only
> acceptable inside IKEv2, where it runs in the encrypted IKE_AUTH after the
> gateway has authenticated with its certificate. Clients must verify that
> certificate. Prefer EAP-TLS, or `cert.conf`, where clients support it.

## Steps

1. Copy one file to `/usr/local/racoon2/etc/racoon2/racoon2.conf`, or
   `include` it from there.
2. Edit every line marked `EDIT`. Those are the public address (it appears
   twice), `my_id`/`peers_id`, and the RADIUS server address.
3. Create the files it names. Secrets (`spmd.pwd`, the PSK and the RADIUS
   secret) must be mode 0600 and owned by root.
4. Run `iked -C -f <file>`. This checks the grammar and the algorithm
   choices. It does not open key, certificate or PSK files; those are read
   when the daemon starts, so check its log on first start.
5. Start `spmd`, then `iked` (or `systemctl start racoon2.target`).

## Client side

- **macOS / iOS** (built-in IKEv2): set Server to the public address,
  Remote ID to the gateway `my_id` and Local ID to the client identity in
  `peers_id`. Set Authentication to "Shared Secret" (`psk.conf`),
  "Certificate" (`cert.conf`) or "Username" (`eap-mschapv2.conf`). See
  `doc/macos-26-27-ikev2-client.md`.
- **Windows** (built-in IKEv2): use EAP-MSCHAPv2 or machine certificates.
  The gateway certificate needs the server name as a SAN, plus the
  serverAuth EKU (and the IP-security IKE intermediate EKU for older
  Windows releases).
- **strongSwan / NetworkManager-strongswan**: `auth = psk`, `pubkey` or
  `eap-mschapv2`, with `remote.id` set to the gateway `my_id`. Several
  linux-matrix rows exercise these authentication methods:
  `i2iinit-charon` (PSK against charon), `i2ieap-mschapv2` (EAP-MSCHAPv2
  against charon via FreeRADIUS), and `i2ipubkey-*` / `i2icert-wire*`
  (certificates, iked<->iked).

All of these configs offer AES-GCM first and AES-256-CBC + HMAC-SHA2-256 as
the fallback. Add `esp_addke_alg { mlkem768; };` to `sa esp_rw` for a
post-quantum child on clients that support RFC 9370 (see
`samples/macos_ikev2.conf`).
