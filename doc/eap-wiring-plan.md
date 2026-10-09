# EAP wiring plan for racoon2 iked (remote-access EAP on Fedora .165)

Status: **plan for review** — no code shipped. Authored 2026-10-06.

## 1. Goal

Add remote-access **EAP** authentication to the racoon2 IKEv2 server so that
Windows / Android / Cisco AnyConnect / strongSwan road warriors can
authenticate with a username+password (EAP-MSCHAPv2) or a client certificate
(EAP-TLS), using an **AD / KDC / RADIUS** deployment colocated on the Fedora
prod VPN box `192.168.0.165`. Today the server is PSK/cert only (proven against
iPhone/macOS), which excludes the huge class of EAP-based RA clients.

## 2. Architecture decision

**Recommended: iked as a RADIUS client.** iked does not implement EAP methods
in-process; instead it runs the EAP *framing* (RFC 3748) and forwards each EAP
message to a RADIUS server via `Access-Request` / `Access-Challenge` /
`Access-Accept`, carrying the EAP packet in the standard `EAP-Message` (79)
attribute with `Message-Authenticator` (80) and the shared-secret MD5 vendor
authenticator. The RADIUS server (FreeRADIUS) runs the actual EAP-MSCHAPv2 /
EAP-TLS method and validates against AD / KRB5 / users.

- Modular: iked stays authentication-method agnostic; adding a method is a
  FreeRADIUS config change, not a C change.
- Lets FreeRADIUS own the AD/LDAP/Kerberos/ntlm_auth bindings.
- Matches strongSwan's model (charon has a RADIUS EAP client)

**Rejected: in-process EAP library** (linking wpa_supplicant's EAP stack or a
vendored lib) — heavier, ties iked to one method stack, duplicates AD bindings,
and drags a large TLS/MSCHAPv2 code surface into the IKE daemon. Only revisit if
single-round-trip latency or a dependency-free standalone is required later.

## 3. EAP-in-IKEv2 mechanics recap

- EAP runs **only inside IKE_AUTH**, as the responder to `N(EAP[A])` /
  `N(EAP[P])` (payload type 48). It is tunnelled in the **already-encrypted**
  IKE_AUTH request, so the responder already holds `SK_e`/`SK_a` before any EAP
  exchange.
- EAP is **initiator-identity only** (RFC 7296 §2.16). The responder never
  sends EAP of its own; the pressure for the *server* is to terminate the
  client's EAP, which is exactly this plan.
- **RFC 5998 EAP-only auth**: when a server is EAP-only there is no AUTH payload
  in the responder's IKE_AUTH; instead both sides derive the EAP-authenticated
  keys from the MSK and the responder proves possession via the same
  SK_p/SK_Pr-derived AUTH. Requires `N(EAP_ONLY_AUTH)` negotiation.
- **RFC 4739 multiple auth** is available when both EAP and a legacy/PSK auth
  are used; not required for the first milestone (EAP-only server).
- **Key derivation**: after EAP success, the method yields an MSK.  For
  EAP-MSCHAPv2 the two 16-octet MS-MPPE keys (RFC 3079 §3.3) come back from
  RADIUS as Recv-Key∥Send-Key ∥ 32 zero octets = 64-octet MSK
  ([MS-CHAP] 3.1.5.1); EAP-TLS RFC 5216 gives a 64-byte MSK.  iked uses the
  MSK as the shared secret in RFC 7296 §2.16 / §2.15:
  `AUTH = prf(prf(MSK, "Key Pad for IKEv2"), SignedOctets)`.

EAP packets are raw `Code/Identifier/Length/Type/Data` with a 4-byte header and
a 1-byte method type; a 0-length Identity response and the
Success/Failure/Nak codes are the skeleton any method must handle.

## 4. Code touch-points in racoon2

1. **EAP framing module** — where payload type 48 is currently `#ifdef notyet`
   in `iked/ikev2.c` (the `IKEV2_PAYLOAD_EAP` case regions, ~lines 2830 /
   2895 / 3692 / 4233). New `ikev2_eap.c`: encode/decode EAP Request/Response
   (RFC 3748), carry `Identifier`, and orchestrate the Request→Response
   round trips across the IKE_AUTH state.
2. **RADIUS client module** — `ikev2_radius.c` (or in `lib/`): packet
   encode/decode for `Access-Request/Challenge/Reject/Accept`, UDP 1812,
   shared-secret MD5 authenticator, `EAP-Message`(79)/`Message-Authenticator`
   (80/Vendor 0), retry/timeout, and Response-Authenticator verification.
3. **RFC 5998 EAP-only-auth wiring** — advertise `N(EAP_ONLY_AUTH)`, suppress
   the responder AUTH payload, and derive AUTH from the EAP MSK instead.
4. **Key derivation** — after a successful EAP exchange (Access-Accept +
   MSK), iked sets the EAP-derived MSK as the shared secret for the IKE
   AUTH computation (RFC 7296 §2.16, §2.15):
   `AUTH = prf(prf(MSK, "Key Pad for IKEv2"), SignedOctets)`.
   **Must compose with — not double-mix with — the
   existing ADDKE (RFC 9370), IKE_INTERMEDIATE (RFC 9242) and PPK (RFC 8784)
   derivation chain** (a PPK'd SK_d would again diverge from a peer that defers
   PPK, as the 2026-09-28 fix did; EAP MSK is mixed at the EAP-success stage,
   after the key-exchange material, and the existing chain must treat it as one
   more KEEP-ORDER input, not re-run the mix).
5. **Config grammar** — `iked/ike_conf.c` + `lib/cftoken.l` + `lib/cfparse.y`:
   per-remote `kmp_auth_method { eap; }`, plus an `eap { }`-style block for the
   RADIUS server address and a **secret file reference** (`radius secret file
   "<path>"`) — never a literal secret in the config.
6. **Dependency** — if RADIUS-client-only (recommended), the only new runtime
   dependency is nothing beyond sockets + OpenSSL already linked; the RADIUS
   HMAC/MD5 and EAP-Message framing are self-contained ~1–1.5k LOC. If the
   in-process EAP library path were chosen, it adds a heavy third-party dep —
   avoided.

## 5. What is actually on .165 (measured 2026-10-06)

Packages present: freeradius-3.2.8, krb5-server-1.22.2, samba-winbind-4.24.6, realmd-0.17.1. sssd is not installed. Services: sssd inactive (not installed), krb5kdc inactive, radiusd failed, smb inactive, winbind inactive. `realm list` is empty. `/etc/krb5.conf` has no default_realm (the EXAMPLE.COM stanza is commented). `/etc/raddb` exists, including `clients.conf.d-racoon2`, but radiusd is not running.

So the box has the packages and a FreeRADIUS tree, and it does not have a joined AD domain or a running KDC. ntlm_auth against AD cannot work until someone joins the realm (or points FreeRADIUS at a LAN domain controller). That join is an operator decision, not something this plan invents. Until then the first milestone is: bring radiusd up on 127.0.0.1 with a local test user, prove the iked RADIUS framing, and only then attach winbind.

The rest of this section is the target shape once that join exists, not the current state.

Recommended server stack on the Fedora box (or a LAN host):

```ini
# /etc/raddb/clients.conf — the IKE server is a RADIUS client
client 127.0.0.1 { ipaddr = 127.0.0.1; secret = RADIUSSECRET; shortname = iked; }
```

```ini
# /etc/raddb/mods-available/eap
eap {
    default_eap_type = mschapv2
    mschapv2 { with_ntdomain_hack = yes; send_error = no; }
    tls { /* cert/key for EAP-TLS later */ }
}
```

Authorisation against **Active Directory / Samba** (`ntlm_auth` helper keeps the
AD user database authoritative):

```ini
# /etc/raddb/sites-available/default → authorize{} / authenticate{}
# or a per-realm auth-type = ntlm_auth
```

```ini
# /etc/raddb/mods-available/ntlm_auth (rlm_mschap → auth_type = ntlm_auth)
ntlm_auth {
    ntlm_auth = "/usr/bin/ntlm_auth --request-nt-key --username=%{mschap:User-Name}"
    ... # winbind/sssd provides the AD backend
}
```

(Alt: `rlm_pap`/`rlm_ldap` against a pool; or a pure KRB5 KDC as the account
source with EAP-TLS/PEAP carrying the credential exchange.)

The `.165` box is the natural home: iked → `127.0.0.1:1812` → FreeRADIUS →
AD/winbind, no new network dependency.

## 6. Config grammar proposal (racoon2.conf)

```
remote client {
    ikev2 {
        kmp_auth_method { eap; }
        eap {
            radius_server "127.0.0.1";
            radius_port 1812;
            radius_secret_file "/etc/racoon2/radius-secret";
        }
    }
}
```

## 7. Key derivation (AUTH) with EAP

RFC 7296 §2.16 substitutes the EAP-derived MSK for the shared secret in
§2.15, so the responder's AUTH is:

`AUTH = prf(prf(MSK, "Key Pad for IKEv2"), SignedOctets)`

There is **no** `Ka = prf+(SK_d, N(p) || MSK)` remix of `SK_d` in that
section.  EAP-MSCHAPv2 supplies its 64-octet MSK as
Recv-Key∥Send-Key∥32 zero octets (RFC 3079 §3.3, [MS-CHAP] 3.1.5.1);
EAP-TLS supplies a 64-octet MSK (RFC 5216).  The MSK is used only in the
AUTH computation, on top of the existing key schedule — it must not
disturb the ADDKE/I_INTERMEDIATE/PPK key-derivation chain, whose SKEYSEED
outputs stay as the peer computes them.

## 8. Security notes

- **EAP-MSCHAPv2 is weak** (dictionary/offline with capture; the MPPE keys are
  the only secret). It is acceptable inside the encrypted IKE_AUTH tunnel
  (which already protects it), and is the compatibility method for Windows RA /
  AnyConnect. Prefer **EAP-TLS** for new deployments; MSCHAPv2 is the pragmatic
  first milestone.
- EAP is initiator-only (RFC 7296): the **server** terminates client EAP;
  racoon2-as-*initiator* EAP is later work.
- Key derivation must compose with the existing ADDKE/intermediate/PPK chain
  (see §4.4) to avoid another PPK-style divergence bug.

## 9. Milestones / LOC estimate

1. EAP framing + Identity/`Nak`/Success/Failure skeleton (phase 1 RFC 3748) —
   ~600 LOC.
2. RADIUS client (Access-Request/Challenge/Reject/Accept, EAP-Message,
   Message-Authenticator, retry) — ~800 LOC.
3. EAP-MSCHAPv2 via FreeRADIUS+ntlm_auth/AD end-to-end on .165 — wiring ~400
   LOC + FreeRADIUS config.
4. EAP-TLS + RFC 5998 EAP-only-auth + MSK→SKEYSEED — ~500 LOC.
5. Config grammar + docs + matrix rows — ~300 LOC.

Total ~2.5–3 kLOC for a production EAP-MSCHAPv2/EAP-TLS server path, first
milestone (framing + RADIUS + MSCHAPv2) ~1.8–2 kLOC.

## 10. Open questions

- Identity handling: use the EAP Identity as the IKEv2 ID or require `ID_RFC822`?
- MSK length policy (128-byte EMSK vs method MSK) for EAP-TLS.
- FreeRADIUS session/accounting hooks (start/stop/interim) — out of scope for
  auth-only first milestone.
- Whether to also expose IKEv1 XAuth/mode-config (currently `ENABLE_HYBRID`
  scaffolding only); likely a separate later workstream.
