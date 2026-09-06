# Expected macOS 26 / 27 IKEv2 client (native)

First-client verification is **not done**. Fill the checklist at the bottom when a Mac actually connects. Do not treat this file as proof that NAT-T or Child SA install works.

Responder on this box (WSL Ubuntu):

- Config: `/usr/local/racoon2/etc/racoon2/macos_ikev2.conf`
- Sample in tree: [samples/macos_ikev2.conf](../samples/macos_ikev2.conf)
- IKE identity: Remote ID `racoon2.wsl`, Local ID `macos.client`
- Auth: IKEv2 PSK only (no EAP, no cert)
- IKE SA: AES-256/128-CBC, PRF/INTEGR HMAC-SHA2-256, DH 14 (`modp2048`) then 15 (`modp3072`)
- Child SA: ESP AES-GCM-16 (`aes_gcm` + `non_auth`), fallback AES-CBC + HMAC-SHA2-256
- NAT-T UDP 4500 is configured; **not** claimed working until `ip xfrm state` shows `encap espinudp`

## System Settings (Tahoe 26, expected same spine on 27)

Path used by current native client (Ventura+; Tahoe keeps it):

1. Apple menu → System Settings → VPN
2. Add VPN Configuration → IKEv2
3. Authenticate as admin if prompted
4. Fill the sheet, Create, then toggle Connect

If Add VPN Configuration does nothing after auth: known Tahoe bug, corrupt `/Library/Preferences/com.apple.networkextension.plist`. That is a Mac-side repair, not a racoon2 issue.

### Fields that must match this responder

- Display Name: anything
- Server Address: a **reachable** IPv4 of the Ubuntu box (WSL NAT notes below). Not the FQDN unless DNS exists.
- Remote ID: `racoon2.wsl` (must equal iked `my_id`)
- Local ID: `macos.client` (must equal iked `peers_id`)
- User Authentication: **None** (do not pick Username / EAP)
- Machine Authentication: **Shared Secret**
- Shared Secret: contents of `/usr/local/racoon2/etc/racoon2/psk/macos.psk` on the Ubuntu box (`sudo cat`; 32 random bytes from `pskgen -r -s 32`)

Leave certificate / EAP / password empty. A Username+password profile is EAP-MSCHAPv2; this iked remote is `kmp_auth_method { psk; }` only.

MDM equivalent (not required for a manual first client): declaration type `com.apple.configuration.network.vpn.ikev2`, `Authentication.Method` = `SharedSecret`, `LocalIdentifier` / `RemoteIdentifier` as above.

## Crypto Apple will send (26 / 27)

macOS 26 Tahoe **removed** from the built-in IPsec stack: DES, 3DES, SHA1-96, SHA1-160, DH groups below 14. This responder does **not** offer those.

Apple IKE SA payload defaults (MDM `IKESecurityAssociationParameters` when the profile omits overrides):

- Encryption: `AES-256` (CBC). `AES-256-GCM` is allowed; **iked cannot do IKE GCM** (no RFC 5282). If a profile forces IKE GCM, the SA will not match.
- Integrity: `SHA2-256`
- DH: `14` (modp2048). Groups `1,2,5` gone on 26+. Group **19** (ECP256) is common on some vendor “use Apple defaults” guides; **this tree has no ECP groups**. If the Mac proposes only 19, negotiation fails until the profile sets DH 14 or 15.
- Child SA: prefer ESP AES-GCM-16 here; CBC+SHA2-256 is the fallback.

macOS 26+ MDM can set `Post Quantum Key Exchange Methods` (RFC 9370 ADDKE1–7) and RFC 8784 PPK. **Not implemented** in this racoon2 tree. Leave those keys unset on the client.

macOS 27 MDM adds `Network Routing` on the IKEv2 declaration. Manual Settings UI is not expected to expose it. Ignore until a 27 client is in hand.

Do **not** use L2TP/IPsec on 26/27 against this box. The L2TP UI may still exist; Tahoe still rejects 3DES/SHA1/DH<14 on that stack, and this install is IKEv2-only.

## What this first install will not do

- Inner IPv4 via IKEv2 CP: racoon2 CP is experimental; vals has a pool but the Mac may still propose `0.0.0.0/0`. Confirm traffic selectors in iked logs, not by assuming a utun address.
- IKE AES-GCM, DH19, ML-KEM / RFC 9370
- v6-in-v4 / Apple NAT-T as a first-class claim (needs live `ip xfrm` after CHILD_SA)
- Socket-activated spmd: `spmd` still unlinks `/run/racoon2/spmif` before LISTEN_FDS. Test units are Type=simple `-F` without `.socket`

## Reachability (WSL2)

Ubuntu address last configured: `172.21.140.169` (WSL virtual NIC). A LAN Mac cannot hit that unless:

- `.wslconfig` has `networkingMode=mirrored`, **or**
- UDP 500 and 4500 are forwarded from the Windows LAN IP onto that WSL address (Hyper-V/mirrored path; `netsh interface portproxy` is **TCP-only** and will not carry IKE)

Until one of those is true, use a Mac that can route to `172.21.140.169`, or test from Windows/WSL itself. `ip xfrm` after a failed connect from a Mac that never reached UDP 500 proves nothing about XFRM.

Load `xfrm_user` and `esp4` **before** start (`ProtectKernelModules` on the stock units cannot modprobe).

## First-client checklist (fill in)

On the Mac:

- [ ] Settings → VPN → IKEv2 sheet saved with IDs above
- [ ] User Auth = None, Machine Auth = Shared Secret
- [ ] Connect toggled; status Connected or the exact error string
- [ ] macOS version (26.x / 27.x) and whether a VPN profile overrode SA params (GCM / DH19 / PQC)

On Ubuntu (root):

- [ ] `ss -ulnp | grep -E ':(500|4500) '` shows iked
- [ ] `journalctl -u racoon2-iked -n 80` (or iked `-l` file) shows IKE_SA_INIT / IKE_AUTH / Child SA
- [ ] `ip xfrm state` SPIs match iked; GCM is `rfc4106(gcm(aes))` **or** CBC+hmac-sha256
- [ ] `ip xfrm policy` in/out/fwd present; tunnel sel 0/0 if that is what Apple proposed
- [ ] NAT-T: `encap espinudp` only if the Mac is not on-path to 500
- [ ] `/proc/net/xfrm_stat` `XfrmInNoStates` / `XfrmInTmplMismatch` did not climb on a successful ping

Pass/fail is that `ip xfrm` dump, not the Mac menu saying Connected.
