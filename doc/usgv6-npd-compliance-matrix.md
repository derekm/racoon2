# USGv6 NPD v1.3 — compliance matrix for racoon2

Maps the **ICSA Labs *Network Protection Devices* test specification
v1.3** (USGv6 NPD, 2011-08-19,
`https://www.iol.unh.edu/sites/default/files/testsuites/ipv6/USGv6_NPD_v1.3.pdf`)
to the racoon2 IPsec/IKE stack.

The USGv6 NPD spec is a **device-level** test plan for firewalls, Intrusion
Detection Systems, and Intrusion Prevention Systems.  racoon2 is a software
IPsec/IKE component (iked/spmd) of such a device — it is not itself a
firewall or an IDS/IPS.  The matrix therefore states, per test, whether the
requirement falls on racoon2 directly, on the surrounding platform (Linux
kernel XFRM / netfilter), or is out of the TOE's scope for the compliance
claim.

Verdict legend:

- **RA** (racoon2) — requirement lands on iked/spmd or trafconfd; evidence is
  the NDcPP CPL/KAT matrix (`samples/linux-matrix`, `mk_report.sh`).
- **PLAT** — requirement lands on the embedding Linux platform (kernel
  XFRM/SPD, netfilter, systemd, host networking); racoon2 only supplies the
  IKE/ESP user-plane that configures XFRM.
- **SCOPE** — outside the NPD/IPsec compliance claim for this TOE (e.g. a
  firewall filtering or IDS/IPS detection function racoon2 does not
  perform); noted for completeness, not a claim.
- **CONF** — administrative/configuration surface requirement; satisfied by
  iked.conf / spmd control channel / config-tool.

Coverage reference: the NDcPP v3.0e compliance report and its
`FCS_IPSEC_EXT.1` cell map (A1–A14) plus crypto KAT cells (B1–B6) are the
authoritative evidence set between racoon2 and any *IPsec* requirement here;
USGv6 NPD §2.3.2 references exactly that (see below).

---

## 1. Common requirements

| Test | Requirement (short) | Verdict | Evidence / note |
|------|---------------------|---------|-----------------|
| 1.1.1 | NPD may implement only the IPv6 connectivity needed for its security function; **not tested** in this plan | SCOPE | Referred out to the Conformance/Interop test selections. No racoon2 claim. |
| 1.2.1 | Dual stack — MAY support IPv4 and IPv6; only IPv6 protection in scope | RA | racoon2 is v4/v6 agnostic (single IKE engine binds both address families); the matrix runs IPv6 netns rows (`i2ike*`). |
| 1.3.1 | Administrative interface can configure protective functionality | RA/CONF | iked.conf: policies, algorithms, lifetimes, auth; `verify_id`, `proposal_check`; config-tool surface. |
| 1.3.2 | Modify logging/alert facility configuration | RA/CONF | `loglevel`/`logfile` knobs; syslog target. |
| 1.4.1 | Admin controls restricted to authorized users | PLAT/SCOPE | spmd control channel authentication + OS user permissions; no web/GUI admin surface on the TOE. |
| 1.4.2 | Enforce per-user individual rights if offered | SCOPE | racoon2 exposes no multi-user admin UI; not a claim. |
| 1.5.1 | Admin controls secure from non-authorized access | RA/CONF | spmd login (password-gated control channel); secret never logged (see `cafc7d3`/`a6e13d2`). |
| 1.5.2 | Admin communications secure from outside observation | RA/CONF | local console / unix-domain spmd interface only — no plaintext network admin channel. |
| 1.6.1 | Settings persist through power loss | PLAT | Config files on disk (persistent storage); daemon re-reads at start. |
| 1.7.1/1.7.2 | Configuration-change logging, admin-viewable | PLAT/RA | racoon2 logs config/setup events at start; live knob changes via trafconfd go to log. Full change-audit is a host-logging function. |
| 1.8.1 | Handle fragmented packets (reassemble-and-apply or block) | PLAT | Linux XFRM reassembles before SPD lookup; fragment policy is a kernel/netfilter function, not iked. |
| 1.9.1 | Handle v4/v6 tunneling schemes (analyze or block) | SCOPE/PLAT | 6in4/4in6/6to4/Teredo handling is a firewall/kernel function. racoon2's own tunnel is ESP (see A3). |

## 2. Firewalls

| Test | Requirement (short) | Verdict | Evidence / note |
|------|---------------------|---------|-----------------|
| 2.1.1.1/.2 | Allow/block IPv6 packets to/through interfaces by src/dst address | PLAT | Static-packet filtering is netfilter; racoon2's SPD governs only how it protects its own traffic (PROTECT/BYPASS/DISCARD, A1/A2). |
| 2.1.1.3 | Block illegal source/destination addresses | PLAT | Host/kernel anti-spoofing, `rp_filter`; explicitly not implemented inside racoon2. |
| 2.1.2.1 | Block by Next Header | PLAT | Kernel/firewall function. |
| 2.1.2.2 | Block Type 0 Routing Headers (RH0) | PLAT | Kernel drops RH0; not a racoon2 function. |
| 2.1.3.1 | TCP/UDP port blocking | PLAT | Netfilter. |
| 2.1.3.2 | ICMPv6 by type/code | PLAT | Netfilter; racoon2's ICMPv6 PD handling is separate (trafconfd/6to4-helper use). |
| 2.1.4.1 | Implicit deny — block traffic not explicitly allowed | RA/PLAT | racoon2 SPD has no routing catch-all and scopes UDP 500/4500 BYPASS to IKE ports (**A2** evidence); remaining filter policy is the firewall's implicit-deny. |
| 2.2.1 | Asymmetric controls between internal/external | PLAT | Netfilter/zone policy. |
| 2.2.2 | Allow connection-oriented (TCP) bidirectional | PLAT | Netfilter conntrack. |
| 2.2.3 | Block unsolicited external replies | PLAT | Netfilter stateful inspect. |
| 2.3.1 | **Selectively block ESP and AH traffic** | SCOPE/PLAT | A firewall feature. For a gateway that *terminates* IPsec, ESP/AH to/from the firewall's own addresses is protected-terminated rather than blocked; ESP/AH *pass-through* filtering is netfilter. Not a racoon2 claim. |
| 2.3.2 | **Establish SAs with IPsec hosts/gateways; meet IPsec Security, IKEv2, and crypto requirements for a router per the USGv6 Profile** | RA | **This is the load-bearing IPsec claim.** racoon2's IKEv2/ESP compliance is exactly the NDcPP v3.0e suite — A1–A14 cells + B1–B6 KATs (report). NAT-T, DH groups, AES-GCM, lifetimes, peer auth, identifier binding, parent≥child strength. |
| 2.4.1 | Fail-safe under load — no unauthorized access when resource-exhausted | RA/PLAT | iked has oversized/IKE-session limits and fail-closed NEG behavior (A12/A13/A14 rows); pcap/CPU saturation under full load is a platform availability function. |
| 2.5 | Tunneled traffic handling: analyze inner header or block unanalyzed tunnels | SCOPE/PLAT | Non-IPsec tunnels (6in4 etc.) are kernel/firewall. racoon2's ESP-in-IPsec tunnel itself is covered by A3 + the NAT-T rows. |

## 4. Intrusion Detection Systems

> **§4.2 note:** racoon2 is not an IDS and makes no detection claim (below).

(4.1–4.6, 5.1–5.2) target signature/anomaly/port-scan detection products.
They are **SCOPE** for this TOE; the relevant *IPsec-relevant* behaviors
the suite does cover are the negative/misbehaving-peer rows (IKE_SA_INIT
drop, drop576, reqdrop, silence, wrong-PSK, id-mismatch, A12-strict — all
fail-closed, matching NPD 4.6/5.2's fail-safe spirit at the IKE layer).

| Test | Requirement (short) | Verdict |
|------|---------------------|---------|
| 4.1 | Detect vulnerability-related attacks | SCOPE (not an IDS) |
| 4.2 | Malformed packet detection | SCOPE (kernel/IDS function; racoon2 parse-failures fail closed — see 4.2 note) |
| 4.3 | Port-scanning detection | SCOPE |
| 4.4 | Tunneled traffic detection | SCOPE |
| 4.5 | Logging and alerts | SCOPE (racoon2 logs its own IKE events; no DPI alerting) |
| 4.6 | Performance under load, fail-safe | RA/PLAT — IKE-session pacing + NEG fail-closed covered; throughput saturation is host |

## 5. Intrusion Prevention Systems

| Test | Requirement (short) | Verdict |
|------|---------------------|---------|
| 5.1 | Implement detection capabilities (from §4) | SCOPE |
| 5.2 | Stop/attenuate detected attacks + logging | SCOPE — racoon2's closest analog is dropping misbehaving peers (NEG rows) |

---

## Summary

- **Direct racoon2 responsibility:** 1.2.1, 1.3.x, 1.4.x/1.5.x
  (administration surface), **2.3.2 (the IPsec/IKEv2/crypto claim)**, plus
  the fail-closed IKE behavior noted under §4/§5.
- **Platform responsibility (Linux host, out of iked):** 1.6.1, 1.8.1,
  2.1.x, 2.2.x, 2.3.1 (pass-through), 2.5, and IDS/IPS loads.
- **Out of scope for a compliance claim:** 4.x/5.x detection/blocking
  (racoon2 is not an IDS/IPS).

### Cross-reference: USGv6 NPD §2.3.2 ↔ NDcPP v3.0e suite

USGv6 NPD §2.3.2 defers the IPsec content to the router's "IPsec Security,
IKEv2, and Use of Cryptographic Algorithm requirements as specified in the
USGv6 Profile."  That content is the same SFR surface the NDcPP v3.0e
`FCS_IPSEC_EXT.1` cells cover.  Mapping:

| USGv6 NPD IPsec content | NDcPP cell |
|--------------------------|-----------|
| IPsec architecture / SPD | A1, A2 |
| ESP tunnel/transport | A3 |
| ESP crypto (AES-GCM mandatory; CBC+HMAC optional) | A4 |
| IKEv2 + NAT traversal | A5 |
| IKE encrypted payload | A6 |
| SA lifetimes configurable | A7/A8 |
| DH group + secret x / nonce | A11/A9/A10 |
| peer authentication (public-key + PSK) | A13 (+A14 identifier) |
| parent≥child strength | A12 |
| crypto KATs (keygen/establish/destroy, AES, sig, RBG) | B1–B6 |

Open items carried from the FP cross-check also apply here: DH group 20
(P-384) is not implemented, and there is no live public-key IKE_AUTH row
(see `mk_report.sh` Appendix A, G1/G2) — both are required for a strict
claim under the USGv6 Profile IPsec content referenced by §2.3.2.
