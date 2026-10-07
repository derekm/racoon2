# ChaCha20-Poly1305 and AES-CCM: what is wired, what is not

Measured on yescorp@192.168.0.165, kernel 7.2.5-200.fc44, OpenSSL 3.5.8, 2026-10-06. A cell is positive only when the probe printed P. A failing cell is not a permanent property of the library; re-run the probe when the OpenSSL build changes.

## Positive

- IKE AES-CCM ICV-12 (transform 15). Probe `ccm_evp_roundtrip` on that OpenSSL: RFC 3610 packet-1 encrypt PASS, L2_M12=P, L4_M12=P. Wired as `encr_aesccm12` and config token `aes_ccm` (16/24/32-byte AES key plus the 3-byte RFC 4309 salt).
- IKE ChaCha20-Poly1305 (transform 28, RFC 7634). RFC 8439 section 2.8.2 tag matched once the plaintext was the RFC string ("...sunscreen would be it."), not a remembered tail. Config token `chacha20_poly1305`. Round-trip of the same call also passed.
- ESP AES-CCM ICV-12 on Linux XFRM. `/proc/crypto` has `rfc4309(ccm(aes))`. `if_xfrm.c` maps `RCT_ALG_AES_CCM` to that name with a 96-bit ICV. Not matrix-rowed in this pass.

## Not positive — do not offer

- IKE AES-CCM ICV-8 and ICV-16. Same probe: L2_M8=F L4_M8=F, L2_M16=F L4_M16=F, with the RFC 3610 ctrl order (SET_L, SET_IVLEN, SET_TAG before the second init; received tag set before the ciphertext update). Not wired. Re-probe before adding them. Do not explain the F as a ctrl-order bug that another reorder will fix; the order already matches the skill probe.
- ESP ChaCha20-Poly1305. `chacha20poly1305.ko` loads, but `/proc/crypto` has no `rfc7539esp` / chacha AEAD name. No XFRM map. `esp_enc_alg chacha20_poly1305` fails config-check (not supported by kernel). IKE use of the same token does not ask the kernel.
- FreeBSD pfkey IDs for CCM and ChaCha. `rct2pfk_enctype` returns 0 for both so config-check logs "not supported" instead of `errx` killing iked. There is no `SADB_X_EALG_*` case in this tree's headers. Do not add a FreeBSD matrix row until the header grows the id and a row can install a real SA.
- ESP CCM ICV-8 and ICV-16 on Linux. The kernel cipher can take those ICV lengths, but there is no separate racoon code for them, and the IKE side of those tag lengths is not a positive KAT. One code, ICV-12, is the wired subset.

## Config

Tokens live in `lib/cftoken.l` / `lib/cfparse.y`. The build regenerates the parser. `aes_ccm` is ICV-12 only. `chacha20_poly1305` is the IKE cipher; using it as an ESP algorithm is a config error until the kernel advertises the AEAD.
