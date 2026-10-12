# NSA IPsec VPN hardening for racoon2

This document maps the three NSA cybersecurity publications to concrete
racoon2 configuration, sample files, and daemon behavior:

* **Securing IPsec Virtual Private Networks** (Executive Summary,
  NSA, June 2020)
  `https://media.defense.gov/2021/Sep/16/2002855930/-1/-1/0/SECURING_IPSEC_VIRTUAL_PRIVATE_NETWORKS_EXECUTIVE_SUMMARY_2020_07_01_FINAL_RELEASE.PDF`
* **Configuring IPsec Virtual Private Networks** (NSA, July 2020)
  `https://media.defense.gov/2021/Sep/16/2002855928/-1/-1/0/CONFIGURING_IPSEC_VIRTUAL_PRIVATE_NETWORKS_2020_07_01_FINAL_RELEASE.PDF`
* **Mitigating Recent VPN Vulnerabilities** (Cybersecurity Advisory,
  NSA, 2019)
  `https://media.defense.gov/2019/Oct/07/2002191601/-1/-1/0/CSA-MITIGATING-RECENT-VPN-VULNERABILITIES.PDF`

The executive summary and the configuring guide are the normative
crypto/algorithm content; the 2019 advisory is the account/management
hygiene content.  Where a requirement is not applicable to racoon2's
model (vendored gateways, web management interfaces, SSL-VPN), that is
stated rather than force-fit.

## 1. Reduce the VPN gateway attack surface

NSA requirements:

* Limit external access to **UDP 500 (IKE), UDP 4500 (NAT-T/IKE over
  ESP-in-UDP), and ESP (protocol 50)** only.
* When possible, restrict accepted traffic to known peer IP addresses.
  Remote-access peers (unknown roaming IPs) cannot be a static ACL; for
  those, an IPS in front of the gateway is recommended.
* Block malformed/anomalous ISAKMP/IKE traffic.

racoon2 mapping:

* Both daemons bind only `:500` and `:4500` (`interface { ike { … } }`).
  There is no management HTTP/HTTPS surface on either daemon — there is
  nothing to firewall for management.
* `spmd` IPC is a **Unix domain socket** (`spmd { unix … }`), never a
  TCP/UDP service.  Set its file mode so only the daemon accounts can
  reach it; keep `spmd_password` out of world-readable files.
* The kernel (via PF_KEY/XFRM) handles ESP; a host firewall should still
  restrict ESP to the VPN peer prefixes.
* `iked`'s SPD is default-discard: a `policy { ipsec_level require }`
  without a matching SA drops, and the kit's SPD template ends with an
  explicit deny-all entry (see the compliance report's default-discard
  cell).  Verify `ip xfrm policy` shows the SPD's final drop entry.

Sample firewall excerpt (nftables):

```
table inet filter {
  chain input {
    type filter hook input priority filter; policy drop;
    udp dport 500 accept
    udp dport 4500 accept
    ip protocol 50 accept
  }
}
```

## 2. Verify only CNSSP-15-compliant algorithms are in use

NSA stated compliance (as of the June 2020 guidance; re-check CNSSP/NIST
periodically — cryptographic agility is an explicit, recurring duty):

IKE/ISAKMP policy (per CNSSP-15 example):

* Diffie-Hellman group: **16** (groups 20, 16, and 15 are the compliant
  set named in the FAQ; group 24 did not exist in the RFC 3526 MODP list
  the guidance references).
* Encryption: **AES-256**.
* Hash: **SHA-384**.

IPsec/ESP policy:

* Encryption: **AES-256**.
* Hash: **SHA-384** (SHA-256 is also in the CNSSP-15/NIST family).
* Block cipher mode: **CBC** (or an AEAD such as AES-GCM per NIST).

NSA explicitly calls out for **detection/removal**: **DES, 3DES, and
Diffie-Hellman groups 1, 2, and 5**.  SHA-1 and MD5 are not CNSSP-15
hashes (legacy/pre-proposal-era).

racoon2 mapping:

* The IKEv2 transform tables in `iked/ike_conf.c`
  (`ikev2_transf_encr[]`, `ikev2_transf_integr[]`, `ikev2_transf_dh[]`)
  still **list** DES, 3DES, MD5, SHA-1, and groups 1/2/5 (plus the other
  RFC-deprecated transforms, see §8) so that a legacy interop config can
  still be written — but **by default iked refuses them**.  Since the
  defaults flip (behavior change), `allow_nsa_deprecated` and
  `allow_rfc_deprecated` are both **off**: a config that offers an
  NSA- or RFC-deprecated transform fails `ike_conf_check` and iked
  refuses to start or reload, e.g.

  ```
  remote r1 ikev2 kmp_enc_alg 3DES-CBC is NSA-deprecated (CNSSP-15) and allow_nsa_deprecated is off - refusing the configuration
  ```

  Turning the class's switch on makes the transform usable again, and
  then the daemon emits a `PLOG_INTWARN` at config load and at
  proposal-build time whenever one of those algorithms is offered:

  ```
  configuring obsolete algorithm 3DES-CBC - remove the suite (NSA/CNSSP-15; see doc/nsa-ipsec-hardening.md)
  configuring RFC-deprecated algorithm MODP2048-224POS (IKE RFC 8247 s2.4 SHOULD NOT) - remove the suite (see doc/nsa-ipsec-hardening.md)
  ```

  This is the "review the current IKE policy" step made explicit at
  load/proposal time: if you see the line, the configuration you shipped
  can negotiate below the CNSA baseline.

* Recommend configurations take the compliant set directly:

  ```
  remote {
    ikev2 {
      kmp_enc_alg      { aes256_cbc; };          # AES-256, not 3DES
      kmp_prf_alg      { hmac_sha2_384; hmac_sha2_256; };
      kmp_hash_alg     { hmac_sha2_384; };
      kmp_dh_group     { modp4096; modp3072; };  # 16, 15 — not 1/2/5
    };
  };
  ...
  sa esp01 {
    esp_enc_alg  { aes256_cbc; };
    esp_auth_alg { hmac_sha2_384; hmac_sha2_256; };
  };
  ```

  (`modp2048` = group 14 is widely deployed and SHA-256 is the NIST
  workhorse; the CNSA-strict posture per the guidance is group 16 +
  AES-256 + SHA-384.  The sample `samples/nsa-fips.conf` below is the
  strict form.)

## 3. Avoid default / vendor configuration settings

NSA: default configurations and wizards "may allow undesired
cryptography suites"; evaluate what they deployed and remove everything
not explicitly configured to the compliant algorithms.

racoon2 mapping:

* `iked` has **no implicit weak default**: unconfigured
  `kmp_enc_alg`/`kmp_prf_alg`/`kmp_hash_alg`/`kmp_dh_group` produce an
  empty offer (`PLOG_INTWARN "kmp_dh_group list is empty"`) rather than
  a vendor default suite — the daemon does not negotiate below what the
  config states (fail-closed).
* The shipped `samples/*.conf` are documentation, not a silent default.
  They now carry the compliant baseline (see §5).

## 4. Remove unused or non-compliant cryptography suites

NSA: leaving extra, non-compliant policies configured creates a
**downgrade attack** surface — a malicious/downgrading peer offering
only obsolete suites can force a connection below the intended strength.
Validate that only compliant policies are configured, and re-validate
periodically (wizards/user error can reintroduce them).

racoon2 mapping:

* With the switches at their default (off) a non-compliant suite cannot
  be configured at all, and a peer can never select one (§8).  When an
  operator turns a switch on, the `PLOG_INTWARN` in §2 is the per-run
  validation: any offer of a listed deprecated algorithm is logged at
  config load and proposal-build time.
* Prefer a config that lists **only** the compliant algorithms (one
  row per SA), rather than a compatibility ladder.  racoon2's proposal
  matching picks the strongest mutually-offered transform; if the config
  also lists weak ones, a weak-only peer negotiates the weak ones.
* `i2i*` matrix rows that deliberately exercise legacy/weak offers are
  test fixtures in `samples/linux-matrix/`, not deployment configs; the
  comment in each fixture states that.

## 5. Sample configuration baseline

`ikectl`/`iked` samples that ship as deployment examples are updated to
the CNSA baseline:

* `samples/default.conf`, `samples/tunnel_ike.conf`,
  `samples/tunnel_ike_natt.conf`, `samples/transport_ike.conf`,
  `samples/transport_ike_natt.conf`, `samples/local-test.conf` — no
  DES/3DES/MD5/SHA-1/groups 1/2/5 in the default offer lists.
* `samples/nsa-fips.conf` (this repository) — a strict CNSSP-15 AUTH+NEG
  example: AES-256-CBC, SHA-384, groups 16/15, PSK placeholders
  only.  Intended as the copy-from baseline.
* `samples/macos_ikev2.conf` and `samples/ikev1_nat.conf` are interop
  fixtures (the matrix asserts them, including hmac-sha1 rows) — their
  algorithm contents are test scope, not a recommendation; the fixture
  headers say so.

## 6. Mitigating Recent VPN Vulnerabilities (2019) — account/management hygiene

NSA requirements applicable to a self-hosted IKE/IPsec gateway:

* **Require strong, ideally multi-factor, authentication.**
* **Resolve credentials if a compromise is suspected**; rotate server
  keys/certificates.
* **Enable logging of authentication and access attempts, configuration
  changes, and traffic metadata**; monitor for anomalous activity.
* **Prefer IKE/IPsec over proprietary SSL-VPN** (racoon2 is IKE, so this
  is native).
* **Do not let administrators authenticate to the gateway from the
  public-facing VPN interface** (racoon2 has no web/management
  interface, so there is nothing to expose; admin IPC is the local
  `spmd` socket with a password, which should only ever be reachable
  from the host or a trusted management network).

racoon2 mapping:

* Authentication: `kmp_auth_method { psk; }` for automation keys;
  certificate AUTH (`pubkey`) with `verify_id`/`verify_pubkey on` for
  peer identity binding.  For remote-access users, pair the IKE layer
  with an external IdP/2FA at the application layer — racoon2 itself
  has no interactive-user/multi-factor concept, and the NSA advisory's
  MFA requirement is satisfied by the identity layer, not by the IKE
  daemon.
* Logging: `iked`/`spmd` log authentication failures and SA events at
  `PLOG_INFO`+ by default (`logmode normal`).  For paths needed by the
  advisory (`syslog`), run iked with systemd `StandardOutput=syslog`,
  keep the journal, and set `dpd_retry`/`dpd_maxfails` to bound dead
  peer reclamation (do not weaken `dpd_delay` to change drop rate).
* Log encryption metadata: the `-P` pcap facility is off by default;
  enable deliberately only when a capture is required, and protect its
  destination.  Do **not** log key material — the tree strips
  SKEYSEED/IntAuth hex from logs; the same rule applies to psk files
  (length/fingerprint comparison only).
* Certificate rotation: `pre_shared_key` and certificate paths are
  runtime files (`spmd.pwd`, `psk/*.psk`, pubkey files); rotating them
  does not require a rebuild, only a daemon restart/SIGHUP.  Replace
  any PSK if a compromise is suspected — NSA: "all keys should be
  replaced" after a weak-crypto negotiation is observed.

## 7. Level of effort / scope

Implemented in this repository (commit history is the evidence):

* `iked/ike_conf.c` — `nsa_deprecated_alg()` + `PLOG_INTWARN` at
  `alglist_to_proppair()`: any offer of DES/3DES/MD5/SHA-1/MODP-768/
  1024/1536 is logged at proposal-build time.  Advisory; never changes
  negotiation.
* `samples/` — deployment samples moved to the compliant baseline;
  fixtures carry an explicit "test scope, not a recommendation" header.
* `samples/nsa-fips.conf` — strict CNSSP-15 copy-from baseline.

Not in scope / explicitly out: vendored-gateway IPS/ACL appliances
(§1 firewall + IPS is host/network policy, partially sample-only here),
web/SAML/MFA identity layers, and SSL-VPN replacement (racoon2 is the
IKE/IPsec side of that recommendation).

## 8. Deprecated-transform switches (`allow_nsa_deprecated`, `allow_rfc_deprecated`)

Two independent directives of the `ikev2 { }` and `ikev1 { }` clauses,
valid in a `remote` and in the `default` clause, gate every deprecated
transform by class
(`iked/ike_deprecated.c` is the classification table, keyed by IANA
transform type, codepoint and protocol context):

| switch | class | covers |
|---|---|---|
| `allow_nsa_deprecated` | NSA/CNSSP-15 obsolete | DES family (DES, DES_IV64, DES_IV32, 3DES), MD5, SHA-1 (PRF, integrity, AUTH method 1 SHA-1 DigestInfo, DSS), MODP groups 1/2/5 |
| `allow_rfc_deprecated` | RFC 8247 / RFC 8221 MUST NOT + SHOULD NOT, RFC 9395 s5 DEPRECATED | e.g. ENCR_DES / RC5 / IDEA / CAST / BLOWFISH / 3IDEA, IKE ENCR_NULL, PRF_HMAC_MD5 / TIGER, AUTH_HMAC_MD5_*, AUTH_DES_MAC, AUTH_KPDK_MD5, groups 1/2/5/22/23/24, ESP 3DES and Blowfish, ESP AUTH_NONE with a non-AEAD cipher (RFC 8221 s6), DSS AUTH (RFC 8247 s3.1) |

The RFC level of one codepoint can differ by protocol (3DES is MAY for
IKE in RFC 8247 but SHOULD NOT for ESP in RFC 8221), so the same token
can need different switches in `kmp_enc_alg` and `esp_enc_alg`.  A
transform in both classes needs both switches.

**Default: both off (behavior change).**  Deprecated algorithms are
refused unless the config explicitly turns the class on:

* **Config load** (`ike_conf_check_consistency`): a deprecated token in
  `kmp_enc_alg` / `kmp_prf_alg` / `kmp_hash_alg` / `kmp_dh_group`,
  `kmp_auth_method` (DSS; `rsasig` with `offer_sig_hash_algorithms off`,
  which pins AUTH method 1 with SHA-1), `esp_enc_alg` / `esp_auth_alg` /
  `ah_auth_alg` / `esp_addke_alg`, or `non_auth` with a non-AEAD cipher
  is a configuration error, and iked refuses to start or reload.  With
  the switch on it is a warning naming the class, RFC section and level.
* **Negotiation**: every received SA payload is filtered before
  matching (IKE_SA_INIT and IKE_SA rekey both roles, IKE_AUTH child,
  CREATE_CHILD and child rekey incl. RFC 9370 ADDKE rounds), so a peer
  can never make iked select a disallowed transform, even as a
  peer-only ADDKE type the matcher would otherwise carry.  RFC 5723
  resume answers TICKET_NACK (full-exchange fallback) and the restart
  restore skips a record whose suite is now disallowed.
* **AUTH**: with `allow_nsa_deprecated` off iked neither signs nor
  accepts AUTH method 1 with a SHA-1 DigestInfo (a peer that did not
  negotiate RFC 7427 fails AUTH closed); DSS (method 3) needs both
  switches.  Method 14 never uses SHA-1, switch or not.

### IKEv1 (RFC 9395)

The same two switches exist in the `ikev1 { }` clause and govern that
remote's IKEv1 side only; the ikev2 clause keeps its own values.

* **IKEv1 itself is RFC-deprecated** (RFC 9395 s3; RFCs 2407-2409 are
  Historic).  A remote that can speak IKEv1 (it has an `ikev1` clause
  and its `acceptable_kmp`, own or inherited from `default`, is unset or
  lists `ikev1`) needs `allow_rfc_deprecated on`.  Off (the default),
  the configuration is refused:
  `remote X ikev1 acceptable_kmp ikev1 is RFC-deprecated (IKEv1 RFC 9395 s3 DEPRECATED) and allow_rfc_deprecated is off`.
  On, it loads with a warning to migrate the remote to IKEv2, and at
  negotiation time `get_ph1approval` refuses IKEv1 for a remote whose
  switch is off.
* **Per-remote override.**  The value in a remote's own `ikev1` clause
  overrides the `default` clause.  Turning one legacy peer on therefore
  opens nothing on other remotes, nor on the same remote's ikev2
  clause: an IKEv2 remote using hmac_md5 in the same file is still
  refused (`iked/samplecheck.sh`).  `samples/default.conf` leaves the
  switch unset in the default ikev1 clause for this reason.  Each
  shipped sample remote that speaks IKEv1 sets it itself.
* **Algorithms inside IKEv1** are classified separately, by their IKEv1
  codepoints, and need their own class switch as well.  For example,
  IKEv1 with 3DES needs `allow_nsa_deprecated on` too.

RFC 9395 s3 retires IKEv1 together with the IKEv1-only suites and s5
retires the rest, so every RFC-class IKEv1 entry has level DEPRECATED.
IKEv1 never had an RFC 8247-style MUST/SHOULD table.

| IKEv1 attribute (codepoints) | value | NSA | RFC |
|---|---|---|---|
| protocol | IKEv1 | - | RFC 9395 s3 |
| Phase 1 enc (RFC 2409 App A class 1) | 1 DES-CBC, 5 3DES-CBC | yes | RFC 9395 s3 |
| | 2 IDEA, 3 Blowfish, 4 RC5, 6 CAST | - | RFC 9395 s5 |
| | 7 AES-CBC (and later) | - | - |
| Phase 1 hash (class 2) | 1 MD5 | yes | RFC 9395 s3 |
| | 2 SHA-1 | yes | - |
| | 3 Tiger | - | RFC 9395 s5 |
| | 4-6 SHA2-256/384/512 | - | - |
| Phase 1 auth method (class 3) | 2 DSS (also hybrid/XAUTH DSS) | yes | RFC 9395 s3 |
| | 1 PSK, 3 RSA signatures | - | - |
| group (class 4, also the Phase 2 PFS group) | 1 modp768, 2 modp1024, 5 modp1536 | yes | RFC 9395 s3 |
| | 22-24 RFC 5114 groups | - | RFC 9395 s3 |
| ESP transform (RFC 2407 s4.4.4) | the IKEv2 type-1 ids, with RFC 8221 levels (ESP DES MUST NOT, 3DES and Blowfish SHOULD NOT) | as IKEv2 ESP | as IKEv2 ESP |
| Phase 2 auth attribute (RFC 2407 s4.5; AH via AH_MD5/SHA/DES) | 1 HMAC-MD5, 3 DES-MAC, 4 KPDK | yes | MUST NOT, RFC 8221 s6 |
| | 2 HMAC-SHA1 | yes | - |
| | 5-7 HMAC-SHA2 | - | - |
| ESP without auth, non-AEAD cipher | | - | MUST NOT, RFC 8221 s6 |

Config load and negotiation both apply this table: received Phase 1
transforms and Phase 2 bundles (ESP/AH transforms, auth attribute, PFS
group) are screened in `ikev1/ipsec_doi.c` before matching.  A refused
bundle is skipped, and the peer's next bundle is still considered.
`iked -C -f racoon2.conf` checks a configuration without starting the
daemon.

### The deprecated ENCR transforms

ENCR transform IDs 1, 2 and 4-9 are implemented for IKE over the OpenSSL
3 legacy provider (loaded by `eay_init` when present), and offered only
when the switches permit.  Parameters follow the RFCs (RFC 7296 s3.3.5
for the Key Length attribute):

| ID | name | key | IV | Key Length attr | spec |
|---|---|---|---|---|---|
| 1 | DES_IV64 | 64 bit | 8 | none | RFC 1827 / RFC 1829 |
| 2 | DES | 64 bit | 8 | none | RFC 2405 |
| 4 | RC5 | 128 bit (default), 16 rounds | 8 | 128 (absent = 128) | RFC 2451 |
| 5 | IDEA | 128 bit | 8 | none | RFC 2451 |
| 6 | CAST | 128 bit (default) | 8 | 128 (absent = 128) | RFC 2451 / RFC 2144 |
| 7 | BLOWFISH | 128 bit (default) | 8 | 128 (absent = 128) | RFC 2451 |
| 8 | 3IDEA | — | — | — | **no specification** |
| 9 | DES_IV32 | 64 bit | 4 (expanded to IV ‖ ~IV) | none | RFC 1829 s2.1 |

Availability is a runtime property of the linked OpenSSL.  A cipher the
library does not provide is refused by config check with
`kmp_enc_alg <X> unsupported by crypto library`; Debian, Ubuntu and
Fedora build OpenSSL without IDEA and RC5, so those two are refused
there.  ENCR_3IDEA has no specification (IANA lists no reference and RFC
2451 does not define it), so it is always refused with
`kmp_enc_alg IDEA3-CBC unsupported: ENCR_3IDEA has no specification`.

For ESP the kernel decides: Linux XFRM offers `cbc(des)`, `cbc(cast5)`
and `cbc(blowfish)` (no IDEA, RC5, 3IDEA, or the DES_IV32/IV64 framings);
FreeBSD `key.c` offers none of them (AES-CBC/CTR/GCM/GMAC, NULL and
ChaCha20-Poly1305 only), so the ESP side is refused there with
`not supported by kernel`.

Evidence: `iked/deprtest` (classification table), `eaytest legacycipher`
(KATs), and the `i2i-nsawarn*` / `i2i-cipher-*` matrix rows on Linux and
FreeBSD plus the `ikev2-netns-{des,cast,blowfish}` strongSwan interop
rows on Linux.
