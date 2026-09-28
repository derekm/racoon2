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
  still **list** 3DES, MD5, SHA-1, and groups 1/2/5 so that a legacy
  interop config can still be written — but the daemon now emits a
  `PLOG_INTWARN` at proposal-build time whenever one of those algorithms
  is actually offered:

  ```
  configuring obsolete algorithm 3des_cbc - remove the suite (NSA/CNSSP-15; see doc/nsa-ipsec-hardening.md)
  ```

  This is the "review the current IKE policy" step made explicit at
  load/proposal time: if you see the line, the configuration you shipped
  can negotiate below the CNSA baseline.  The warning is advisory;
  removing the algorithm from the config makes it go away.

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

* The `PLOG_INTWARN` in §2 is the per-run validation: any offer of a
  listed obsolete algorithm is logged at proposal-build time.
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
