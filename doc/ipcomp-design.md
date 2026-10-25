# IPComp (RFC 3173) — design note & validation

Status: **config-only. The `sa_protocol ipcomp` / `ipcomp_alg`
directives parse, validate, and enter the config tree, and IKEv1 (legacy
racoon code) has IPComp DOI/negotiation plumbing — but there is **no
end-to-end path that installs a compression-enabled IPComp SA into any
kernel backend**, and there is **no IPComp data-plane / compressor code
anywhere in iked or lib** (no DEFLATE inflate/deflate implementation). No
`make check` test covers IPComp. Treat it as a partially-wired but
non-functional feature.

Branch: `int/gsoc2026`. **Note:** the R2DP backend file `lib/if_r2dp.c`
does not exist on this branch — it lives on `feat/r2dp-km-backend`; the
R2DP item below is read via `git show feat/r2dp-km-backend:lib/if_r2dp.c`
and is therefore *not* on this branch.

## What this is / Scope

IPComp (RFC 3173) is IP payload compression for IPsec: a separate
`IPCOMP` SA type (protocol id 4) that can stand alone or be bundled with
AH/ESP. racoon2's configuration language exposes it (`sa_protocol
ipcomp`, `ipcomp_alg`) and the RFC 2394/2395 transform-ids OUI/DEFLATE/LZS
are mapped into the enum. This note documents exactly how far that wiring
goes and where it stops, based on the source on `int/gsoc2026` (R2DP
flagged as above).

Scope is **static-source validation only**: claims below are backed by
`file:line`; behavior that is absent is stated as absent, not inferred.

## Implementation inventory (source of truth: code + `make check`)

### Config grammar / docs
- `doc/config-usage.txt` documents `sa_protocol (ah|esp|ipcomp)`
  (`doc/config-usage.txt:1359`) and `ipcomp_alg (algorithm)` — "It
  defines compression algorithms to be used. It is valid when the
  sa_protocol is ipcomp." (`:1385-1387`). The valid algorithm-type list is
  `oui`, `deflate`, `lzs` (`:368-372`). SA-bundle literals
  `AH_IPCOMP` / `ESP_IPCOMP` / `AH_ESP_IPCOMP` are also named (`:1342-1348`).

### Enum / data model (`lib/rc_type.h`)
- `RCT_SATYPE_IPCOMP` (`rc_type.h:92`) plus the bundle satypes
  `RCT_SATYPE_AH_IPCOMP`, `RCT_SATYPE_ESP_IPCOMP`,
  `RCT_SATYPE_AH_ESP_IPCOMP` (`:98-99`) — the comment at `:93-97` notes the
  bundle types are used internally by the program and "can not be defined
  by the config."
- Compression algorithms `RCT_ALG_OUI, RCT_ALG_DEFLATE, RCT_ALG_LZS`
  (`rc_type.h:55`).
- `struct rcf_ipsec` holds `struct rcf_sa *sa_ipcomp` (`rc_type.h:532`);
  `struct rcf_sa` carries `struct rc_alglist *comp_alg` (`:543`).

### Lexer / parser (`lib/`)
- `cftoken.l:200` keyword `deflate` → `DEFLATE` token; `cfparse.y:201`
  declares `OUI DEFLATE LZS`; grammar at `cfparse.y:1864-1866` maps the
  three keywords to `RCT_ALG_OUI/_DEFLATE/_LZS`.

### iked config validation (`iked/ike_conf.c`)
- `SA_CONF` pulls `comp_alg` (`:6585`); `ike_conf_check_sa` switch on
  `sa_protocol`:
  - `RCT_SATYPE_ESP` / `RCT_SATYPE_AH`: if `sa->comp_alg` is set it is
    **warned and ignored** (`:6609-6614`, `:6629-6634`).
  - `RCT_SATYPE_IPCOMP`: **requires** `comp_alg` (error "sa %s does not
    have comp_alg list", `:6636-6642`); `enc_alg` / `auth_alg` are warned
    and ignored (`:6643-6654`).
  - The declared kernel-support loop over `sa->comp_alg`
    (`rcpfk_supported_comp`, `:6687-6696`) is inside `#ifdef notyet` — it
    is never compiled, so no kernel capability check runs for IPComp.
- `like_conf_check_ipsec` calls `ike_conf_check_sa(ipsec->sa_ipcomp, …)`
  (`:6839`).

The IKEv1 algorithm tables and DOI mapping exist:
- `iked/ikev1/algorithm.c:249-251` maps `oui`/`deflate`/`lzs` to
  `RCT_ALG_*` and DOI `IPSECDOI_IPCOMP_OUI/_DEFLATE/_LZS`
  (`lib/ipsec_doi.h:81-85`), and `alg_ipsec_compdef_doi` (`:698`,
  `:930-931`).
- `iked/ikev1/ipsec_doi.c` wires protocol/transform/attribute checks for
  IPComp: `check_trns_ipcomp` accepts the three transform ids
  (`:2060-2072`); `check_prot_quick` accepts `IPSECDOI_PROTO_IPCOMP`
  (`:1932`); `check_attr_ipcomp` validates enc-mode etc. (`:2481`);
  `check_spi_size` allows **2 or 4** byte SPI for IPComp (`:1955-1975`).
- `iked/ikev1/proposal.c:666-680` builds IPComp proposal transforms from
  `sa->comp_alg` (`trns_id = alg_ipsec_compdef_doi(...)`, auth none).
- `iked/ikev1/pfkey.c` maps IPComp transform ids → `RCT_ALG_*` (`:381-390`,
  `ipsecdoi2rc_calg`) and protocol id → `RCT_SATYPE_IPCOMP` (`:404-407`);
  the SA-param builder sets `e_type` to the calg value (`:576-586`).

### Backend handling (SAD/SPD)
- **Linux XFRM (`lib/if_xfrm.c`, on this branch):** `add_tmpls()` emits an
  IPComp template for `RCT_SATYPE_IPCOMP` and the bundles
  (`:1171-1194`). **However** the SA send path (`xfrm_send_sa`,
  `:1244-1255`) emits only enc/auth/encap/ESN attrs — there is **no
  XFRMA_COMP_ALG (or any compression) attribute** in `if_xfrm.c` (grep
  finds none). So an IPComp SA installs with proto=IPCOMP in the template
  but **no compression algorithm is conveyed to the kernel**. Offload is
  explicitly ESP-only (`:1329-1333`).
- **BSD PF_KEY (`lib/if_pfkeyv2.c`, on this branch):** `set_satype`
  (`:1697-1751`) derives the combined satype from `sa_ipcomp`
  (`spmd/spmd_pfkey.c:1713-1729`), but the `rcpkf_msg` container itself has
  **no compression-algorithm field** — `struct rcpfk_msg`
  (`lib/if_pfkeyv2.h:92-171`) carries `enctype`/`authtype` but no
  `comptype`. `rct2pfk_comptype()` exists (`lib/rc_type.c:334-342`) and
  maps `RCT_ALG_*` → `SADB_X_CALG_*`, but its only caller
  `rcpfk_supported_comp()` is `#if 0`-disabled (`if_pfkeyv2.c:3142-3159`).
  No `SADB_X_EXT_COMP` extension is ever emitted.
- **R2DP (`lib/if_r2dp.c` — on `feat/r2dp-km-backend`, NOT this branch):**
  maps `RCT_SATYPE_IPCOMP` ↔ `R2DP_PROTO_IPCOMP` (`:150,:161`) and the
  SPP bundle bits (`:236-255`), but the forwarder SA encoder rejects it
  outright:
  `if (p == R2DP_PROTO_IPCOMP) { km_seterror(rc, EOPNOTSUPP, "IPComp not supported by r2dp"); return -1; }`
  (`:431-433`).

## What is implemented
- Full config *surface*: `sa_protocol ipcomp` + `ipcomp_alg (oui|deflate|lzs)` are lexed, parsed, stored in `rcf_sa.comp_alg` / `rcf_ipsec.sa_ipcomp`, and semantically validated by `ike_conf_check_sa` (requires comp_alg for IPComp, ignores enc/auth).
- IKEv1 (legacy racoon path) has real IPComp *negotiation* code: DOI protocol/transform/attribute checking, SPI size 2|4, proposal construction from `comp_alg`, and calg mapping (`iked/ikev1/*`). IKEv1 is compiled into iked (`iked/Makefile:160-164`).
- Satype propagation into the SAD/SPD message (`spmd/spmd_pfkey.c:1713-1729`) and per-backend proto/template mapping (XFRM templates, PF_KEY satype, R2DP wire mapping).

## What is not / limits
- **No compressor anywhere.** There is no DEFLATE/LZS/OUI compression
  implementation (no zlib/`inflate`/`deflate`/`z_stream` usage) in `iked/`
  or `lib/` source. IPComp is config/negotiation-only; **no packet
  compression is performed or possible** with the current code.
- **No kernel backend can install a compression-enabled IPComp SA:** the
  shared `struct rcpfk_msg` ABI (`lib/if_pfkeyv2.h:92-171`) has no
  comp-algorithm field, and `if_xfrm.c` emits no `XFRMA_COMP_ALG`. At best
  an IPComp satype/template reaches the kernel with no compression
  algorithm.
- **IKEv2 does not offer IPComp:** the IKEv2 proposal-protocol enum has no
  IPComp entry (`iked/ikev2.h:203-211`: IKE/AH/ESP/FC only). `ikev2_expired`
  explicitly skips IPComp (`goto done`, `iked/ikev2_child.c:3548-3553`).
  Only `IKEV2_IPCOMP_SUPPORTED` (16387) exists as a notify constant
  (`ikev2.h:555-559`) and is parsed in `ikev2_notify.c:1333`.
- **R2DP backend refuses IPComp** outright (`feat/r2dp-km-backend`
  `lib/if_r2dp.c:431-433`).
- **No test coverage:** no `make check` / matrix row exercises IPComp.
- **Compression alg vs. kernel support is never checked:** the
  `rcpfk_supported_comp` call is inside `#ifdef notyet`
  (`iked/ike_conf.c:6687-6696`).

## Risks / open items
- If a *config* with `sa_protocol ipcomp` is accepted but nothing installs
  a working compression SA, the gap is silent — no error is surfaced at
  `iked -C` beyond the (disabled) kernel-capability check.
- Making IPComp real requires, at minimum: a compressor (DEFLATE via zlib
  is the customary choice), an `XFRMA_COMP_ALG`-capable install path for
  the Linux backend and a comp-field in `struct rcpfk_msg`/`SADB_X_EXT_COMP`
  for PF_KEY, an IPComp entry in the IKEv2 proposal enum, and a test that
  round-trips a compressed SA (initiate, install, ping, `ip xfrm state` /
  `setkey -D` shows comp=deflate).
- The bundle satypes (`AH_IPCOMP`, `ESP_IPCOMP`, `AH_ESP_IPCOMP`) are
  program-internal (`rc_type.h:93-97`); there is no config spelling to
  request them, so multi-proto compression bundles are not reachable today.
- R2DP (off-branch) is a deliberate hard-fail; any cross-branch work must
  keep that rejection or implement forwarder compression.
