# Expected macOS 26 / 27 IKEv2 client (native)

**First-client verification: DONE 2026-09-06 with iPhone (iOS Settings
IKEv2, same sheet as macOS).** Live over LTE behind NAT: IKE_SA on UDP
500, float to 4500, `ip xfrm state` shows `encap type espinudp` both
directions, Child SA AES-CBC + HMAC-SHA256 (Apple picked the fallback,
not AES-GCM), CP lease from the address pool, ping/pkt counters climb
when tested. macOS 26/27 should behave identically — same sheet, same
crypto defaults.

Responder on this box (WSL Ubuntu, mirrored networking):

- Config: `/usr/local/racoon2/etc/racoon2/macos_ikev2.conf`
- Sample in tree: [samples/macos_ikev2.conf](../samples/macos_ikev2.conf)
- IKE identity: Remote ID `racoon2.wsl`, Local ID `macos.client`
- Auth: IKEv2 PSK only (no EAP, no cert)
- IKE SA: AES-256/128-CBC, PRF/INTEGR HMAC-SHA2-256, DH 14 (`modp2048`) then 15 (`modp3072`)
- Child SA: ESP AES-GCM-16 (`aes_gcm` + `non_auth`), fallback AES-CBC + HMAC-SHA2-256. iPhone took the fallback.
- NAT-T UDP 4500: **proven** (`encap type espinudp` in `ip xfrm state`)
- ESP ICV: hmac(sha256) at **128 bits** (RFC 4868). The old 96-bit
  truncation (dead XFRMA_ALG_AUTH_TRUNC guard, `fdb120f`+fix) rejected
  every packet from RFC 4868 peers: `XfrmInStateProtoError` climbed,
  `XfrmInNoStates` stayed 0 — ICV mismatch, not a missing SA.
- **CP pool is mandatory**: Apple always sends CFG_REQUEST for an internal IPv4. The remote must have `provide { addresspool <name>; };` and an `addresspool <name> { "a" - "b"; };` block. Without it: `addresspool.c: no address pool specified` → Child SA aborts → iked SEGVs on the retry storm (crash reproduced 2026-09-06, core capture `/tmp/r2core.*`).

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

- IKE AES-GCM, DH19, ML-KEM / RFC 9370
- IPv6-in-IPv4
- Host reboot (resume dump is tmpfs; ESP dies with the kernel). iked restart with a live IKE_SA kept the iPhone Connected 2026-09-08.

## Reachability (WSL2)

Ubuntu address last configured: `172.21.140.169` (WSL virtual NIC). A LAN Mac cannot hit that unless:

- `.wslconfig` has `networkingMode=mirrored`, **or**
- UDP 500 and 4500 are forwarded from the Windows LAN IP onto that WSL address (Hyper-V/mirrored path; `netsh interface portproxy` is **TCP-only** and will not carry IKE)

Until one of those is true, use a Mac that can route to `172.21.140.169`, or test from Windows/WSL itself. `ip xfrm` after a failed connect from a Mac that never reached UDP 500 proves nothing about XFRM.

Load `xfrm_user` and `esp4` **before** start (`ProtectKernelModules` on the stock units cannot modprobe).

## First-client checklist (fill in)

On the Mac:

- [x] Settings → VPN → IKEv2 sheet saved with IDs above (verified on iPhone 2026-09-06)
- [x] User Auth = None, Machine Auth = Shared Secret
- [x] Connect toggled; status Connected
- [x] Client version: iPhone (iOS 26-era Settings spine); **did not** override SA params (CBC IKE, ESP fallback)
- [ ] macOS 26/27 retest when a Mac is in hand

On Ubuntu (root):

- [x] `ss -ulnp | grep -E ':(500|4500) '` shows iked
- [x] journal shows IKE_SA_INIT / IKE_AUTH / Child SA
- [x] `ip xfrm state` SPIs match iked; AES-CBC + `hmac(sha256)`, `encap type espinudp`
- [x] `ip xfrm policy` in/out/fwd present with the leased CP addr (`192.0.2.10` in the live run)
- [x] NAT-T: `encap espinudp` **confirmed** (LTE client behind carrier NAT)
- [x] `/proc/net/xfrm_stat` `XfrmInNoStates` / `XfrmInTmplMismatch` did not climb

Pass/fail is that `ip xfrm` dump, not the Mac menu saying Connected.
