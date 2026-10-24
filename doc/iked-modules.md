# iked IKEv2 module map

`IKEV2_SRC` in `iked/Makefile.am` after the exchange-level split. Each file
owns one exchange or one feature. The roles below come from the files'
headers and their RFCs.

| File | Role |
|---|---|
| `ikev2.c` | Demux and dispatch, IKE_SA glue shared by the exchanges |
| `ikev2_sa_init.c` | IKE_SA_INIT (RFC 7296 §2.6/2.7) |
| `ikev2_cookie.c` | IKE_SA_INIT anti-DoS cookies |
| `ikev2_intermediate.c` | IKE_INTERMEDIATE (RFC 9242), the carrier for ADDKE, IntAuth chain |
| `ikev2_addke.c`, `ikev2_addke_rounds.c` | RFC 9370 additional key exchanges (ADDKE1..7, ML-KEM), initial and rekey rounds |
| `ikev2_sa_auth.c` | IKE_AUTH (RFC 7296 §2.9), with the EAP arm and RFC 8784 PPK handling |
| `ikev2_auth.c` | AUTH payload computation/verification (PSK, RFC 7427 signatures) |
| `ikev2_eap.c`, `ikev2_eap_relay.c`, `ikev2_eap_round.c`, `ikev2_eap_drive.c`, `ikev2_eap_emit.c` | EAP framing (RFC 3748), responder relay state machine, RADIUS round on the worker pool, round driver, IKE_AUTH response composition |
| `ikev2_radius.c` | RADIUS client (RFC 2865/3579) |
| `ikev2_child.c` | CREATE_CHILD_SA (child creation) |
| `ikev2_rekey.c` | IKE_SA and CHILD_SA rekey, including ADDKE rekey followups |
| `ikev2_informational.c` | INFORMATIONAL: DELETE, DPD, notifies (RFC 7296 §2.8) |
| `ikev2_notify.c` | Notify payload construction/parsing |
| `ikev2_mobike.c` | RFC 4555 MOBIKE (responder-follow) |
| `ikev2_config.c`, `ikev2cfg_walk.c` | Configuration payload (CP) and its bounds-checked attribute walker |
| `ikev2_session_resume.c`, `ikev2_resume_ticket.c` | RFC 5723 session resumption exchange and ticket-by-value core |
| `ikev2_resume.c`, `ikev2_resume_rec.c` | Restart resume (keep kernel ESP, restore keys/IDs) and its dump record format |
| `ikev2_qcd.c` | RFC 6290 Quick Crash Detection |
| `ikev2_frag.c` | RFC 7383 fragmentation |
| `ikev2_packet.c`, `ikev2_payload.c`, `ikev2_decrypt.c` | Packet/payload codec and SK/SKF decrypt |
| `ikev2_proposal.c` | SA proposal/transform matching |
| `ikev2_transmit.c` | Transmission, retransmission, message-ID window |
| `ikev2_drain.c` | Runtime drain-redirect table |

Outside IKEv2: `ike_pfkey.c` is the kernel SA interface over the portable
rcpfk_* ABI (`lib/if_pfkeyv2.h`, backends `lib/if_xfrm.c`,
`lib/if_pfkeyv2.c`, `lib/if_userspace.c`). `crypto_workers.c` is the
crypto offload pool, `ike_deprecated.c` the deprecation policy, and
`evloop_epoll.c`/`evloop_select.c` the event loop. spmd
(`spmd/spmd_pfkey.c`) drives the same ABI for the SPD.
