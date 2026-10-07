# ChaCha20-Poly1305 and AES-CCM: what is wired, what is not

Measured on yescorp@192.168.0.165, kernel 7.2.5-200.fc44, OpenSSL 3.5.8, 2026-10-07. A cell is positive only when the probe printed P. A failing cell is not a permanent property of the library; re-run the probe when the OpenSSL build changes.

## Positive

- IKE AES-CCM all three RFC 4309 tag lengths: ICV-8 (transform 14), ICV-12 (15), ICV-16 (16). Probe `ccm_evp_roundtrip` on that OpenSSL: **AES-128/192/256 x M=8/12/16 ALL P/P** with the RFC 3610 ctrl order (SET_L/IVLEN/TAG before the second EVP_*Init_ex; decrypt received-tag set BEFORE the ciphertext update). The earlier "M=8/16 F" (2026-10-06) was a probe-side ctrl-order bug, not a library gap. Wired as `encr_aesccm8/12/16` with config tokens `aes_ccm8` / `aes_ccm` / `aes_ccm16`. Key = AES key || 3-byte RFC 4309 salt (19/27/35 octets); nonce = salt || 8-byte iv (11 octets), L=4.
- IKE ChaCha20-Poly1305 (transform 28, RFC 7634). RFC 8439 section 2.8.2 tag matched once the plaintext was the RFC string ("...sunscreen would be it."), not a remembered tail. Config token `chacha20_poly1305`. Round-trip of the same call also passed.
- ESP AES-CCM ICV-12 on Linux XFRM. `/proc/crypto` has `rfc4309(ccm(aes))`. `if_xfrm.c` maps `RCT_ALG_AES_CCM` to that name with a 96-bit ICV. Not matrix-rowed in this pass.
- ESP ChaCha20-Poly1305 on Linux XFRM. `lib/if_xfrm.c:174` maps `RCT_ALG_CHACHA20_POLY1305` to `rfc7539esp(chacha20,poly1305)` (the COMMA template; `chacha20poly1305` base binds AF_ALG but XFRM only resolves the esp template). The `chacha20poly1305.ko` module autoloads via cryptomgr on first SA install. Key 32B + 4B salt = 72 hex, ICV 128. Matrix rows `i2iinit-esp-chacha` / `-esp-chacha-esn` (gate=box) prove the SAD carries that aead on the Fedora box.
- ESP ChaCha20-Poly1305 on FreeBSD. `rct2pfk_enctype` maps `RCT_ALG_CHACHA20_POLY1305` -> `SADB_X_EALG_CHACHA20POLY1305` (15) when the header defines it; FreeBSD's `esp_xformsw` registers ealg 15 (verified on 15.1: `setkey -D` shows `E: 15` on both mature SAs, child up, data-plane ping). Matrix row `i2iinit-esp-chacha` (FreeBSD) proves it.
- ESP ESN on FreeBSD. `ext_sequence on;` lifts `child_sa->esn` -> `SADB_X_SAFLAGS_ESN` (0x400); FreeBSD `setkey -D` renders `flags=0x00000400 state=mature`. Matrix row `i2iinit-esn` (FreeBSD) proves it. (Linux leg was already positive: `flag esn` in `ip xfrm state`.)

## Not positive — do not offer

- FreeBSD pfkey IDs for CCM. `rct2pfk_enctype` returns 0 for `RCT_ALG_AES_CCM`/`RCT_ALG_AES_CCM8`/`RCT_ALG_AES_CCM16` so config-check logs "not supported" instead of `errx` killing iked. There is no CCM ESP ealg in this tree's headers (FreeBSD/NetBSD define none). Do not add a FreeBSD CCM-ESP row until the header grows the id and a row can install a real SA. (ChaCha ealg 15 IS present on FreeBSD — see Positive.)
- ESP CCM ICV-8 and ICV-16 on Linux. The kernel cipher can take those ICV lengths, but there is no separate racoon code for them (only ICV-12 is wired via `rfc4309(ccm(aes))` 96-bit). IKE CCM offers all three tag lengths (see Positive); the ESP leg stays ICV-12.

## Config

Tokens live in `lib/cftoken.l` / `lib/cfparse.y`. The build regenerates the parser. `aes_ccm8` / `aes_ccm` / `aes_ccm16` are IKE transforms 14/15/16 (ICV-8/12/16). `chacha20_poly1305` is wired as BOTH an IKE cipher and an ESP algorithm (Linux XFRM via `rfc7539esp(chacha20,poly1305)`, FreeBSD via ealg 15).
