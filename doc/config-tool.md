# Easy configuration tool — plan/spec (roadmap adoption)

Adopting two original `README.md` "features to support" items that were never
built: **English documentation** (audited — see below) and **easy configuration
tool**. This spec is the design the tool should be built to.

## 0. Problem

racoon2's config is a C-grammar DSL (`lib/cfparse.y`, `lib/cftoken.l`) with
~90 knobs across 9 top-level blocks (`interface`, `resolver`, `remote`,
`selector`, `policy`, `ipsec`, `sa`, `spmd`, `addresspool`, `external`). Today
the only way to get a correct file is to hand-edit a `samples/*.conf`. Small
semantic mistakes are easy (a `remote_index` that names no `remote`, a
`selector` whose `src`/`dst` direction mismatches its `policy`, `ipsec_level`
typos, a missing `sa_protocol`) and fail only at `iked -f` parse time.

No machine-readable schema exists, and no generator/validator ships.

## 1. Deliverables

1. **`samples/racoon2-schema.json`** — a JSON Schema for a single
   configuration *payload* (one process = one interface/remote/selector/
   ipsec/sa set), plus `racoon2-schema-<kmp>.json` for the `ikev2` / `kink`
   remote kmp blocks. The schema is the single source of truth for "what a
   correct config looks like".
2. **`utils/racoon2-config.py`** (Python 3, stdlib + `jsonschema`) — CLI that
   validates a JSON/YAML payload against the schema (semantic checks the
   syntax alone cannot catch) and pretty-prints it as a racoon2.conf, or the
   reverse (parse an existing `.conf` and normalize it to JSON).
3. **Ground-truth gate** — every generated config must pass the real parser:
   `racoon2-config gen input.json > cfg && iked -F -f cfg` (non-root, expect
   privileged-bind exit but **no** `syntax error`/`no proposal chosen`). This
   keeps the schema honest against the DSL.
4. **CI tile** in the linux-matrix: round-trip a set of sample payloads
   (racoon2.conf, macos_ikev2.conf, the i2i initiator/responder) through
   gen→parse and assert zero parser errors.

## 2. Design principles

- **Schema derived from the parser, not hand-maintained.** The grammar + fixer
  structures (`rcf_*` in `lib/cfsetup.c`) are the authoritative field lists.
  A `gen-schema` helper prints the enum/option sets the fixers accept so the
  schema's `enum`/`patternProperties` match what `cfparse.y`/`cftoken.l`
  actually tokenize. Do not invent option names — pull them from the lexer.
- **"All possible correct configs."** The schema must be able to express every
  construct the grammar accepts (all kmp protocol blocks, dh groups, alg
  lists, notifs), and the generator must refuse anything the grammar cannot
  (mirrors the parse gate). Completeness is measured by: for each
  `samples/*.conf`, gen(schema-payload-of-that-conf) parses clean.
- **Semantic cross-block validation the parser can't express:**
  - `remote.ikev2[key].MAC` (e.g. `peers_id`) ↔ `selector`/`policy` linkage;
  - `policy.remote_index` exists; `policy.ipsec_index` exists;
    `ipsec.sa_index` exists; `sa.sa_protocol` is `esp`/`ah`/`ipcomp`;
  - `ipsec_mode` ∈ tunnel/transport; `ipsec_level` ∈ require/use/unique;
  - `selector` `in`/`out` direction matches `policy` direction;
  - kmp tar_block/dh/PRF/hash/cipher sets are non-empty and mutually
    available (e.g. GCM sa needs `non_auth`; CBC needs an auth alg);
  - ADDKE: `esp_addke_alg` only with `--enable-addke`;
    `addke_required`/`addke_unrequested` valid on the `ikev2` kmp.
- **Deterministic output**: stable sort of list-typed knobs; reproducible byte
  output; the generated file needs no hand-editing to load.
- **No secrets in the tool**: `pre_shared_key` is a path, never inline
  material; the tool never reads PSK contents.

## 3. Payload shape (draft JSON Schema skeleton)

```jsonc
{
  "interface":   ["ike", "spmd", "spmd_password", "bypass"],
  "resolver":    [],
  "remote":  [{ "name": "", "acceptable_kmp": [], "ikev2": {...},
                "ikev1": {...}, "kink": {...}, "selector_index": [] }],
  "selector":    [{ "name": "", "direction": "in|out", "src": [], "dst": [],
                    "policy_index": "" }],
  "policy":      [{ "name": "", "action": "auto_ipsec", "remote_index": "",
                    "ipsec_mode": "", "ipsec_index": [], "ipsec_level": "",
                    "peers_sa_ipaddr": "", "my_sa_ipaddr": "" }],
  "ipsec":       [{ "name": "", "ipsec_sa_lifetime_*": 0, "sa_index": [] }],
  "sa":          [{ "name": "", "sa_protocol": "esp", "esp_enc_alg": [],
                    "esp_auth_alg": [], "esp_addke_alg": [], "keymat": "" }],
  "spmd":        [],
  "addresspool": [],
  "log":         []
}
```

## 4. English-docs audit (the other adopted item)

The doc corpus is bilingual (every `.ja.txt` has an EN twin) and current:
`config-usage.txt` documents `addke_required`/`addke_unrequested`;
`addke-design.md`, `int-gsoc2026.md`, `macos-…ikev2-client.md` are EN. The
two new tools above keep docs *machine-checkable*: the `gen-schema` helper
cross-checks that every `config-usage.txt` keyword tokenizes in `cftoken.l`
(violations = a documented key that the parser rejects, or an undocumented
key).
