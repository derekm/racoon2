# Session resumption tickets (RFC 5723): policy edges

This page describes what iked does today, with code references, for three
ticket questions that deployments ask about: identity binding, multiple
ticket keys, and clocks. Resumption is **off by default**
(`session_resumption off`). Turning it on requires a
`session_resume_ticket_key` file of exactly 32 raw bytes; any other length is
refused (`r2ticket_key_load`, iked/ikev2_resume_ticket.c).

```
remote rw { ikev2 {
	session_resumption on;
	session_resume_ticket_key "/usr/local/racoon2/etc/racoon2/ticket.key";  # 32 bytes, 0600
	session_resume_ticket_lifetime 86400;   # seconds; the default
}; };
```

## 1. IDi binding

- A ticket seals the original IDi and IDr, the SPIs, the negotiated SA, the
  old SK_d, the auth method, an absolute expiry and the certificate notAfter.
  It is encrypted with AES-256-GCM under a per-ticket subkey,
  `HMAC-SHA256(ticket key, key_id)`, where key_id is derived from the SA's
  SPIs. A peer cannot forge or edit the identities inside.
- **The ticket's IDi is re-checked on every resume.** On the resumed IKE_AUTH,
  iked runs the same `peers_id` check as a fresh IKE_AUTH
  (`ikev2_peer_id_ok`; see the trust-boundary comment in
  iked/ikev2_session_resume.c). If `peers_id` was tightened after a ticket was
  minted, that ticket is refused. A ticket does not carry the old policy
  forward.
- **The certificate expiry carries over, but revocation does not.** RFC 5723
  resume has no CERT payload, so the chain is not re-validated. The
  certificate's notAfter is stored in the ticket (`cert_due`), and a resume
  after notAfter gets TICKET_NACK. A certificate revoked after mint stays
  resumable until the ticket expires. **`session_resume_ticket_lifetime`
  therefore bounds how long a revocation takes to apply**, so keep it short
  wherever revocation matters.
- **Tickets are single use** (RFC 5723 s4.3.1). The used-ticket cache is
  stored on disk next to the ticket key file (`ticket-replay/`). It survives
  restarts and is shared by every iked that loads the same key *path* on the
  same filesystem. With 4096 unexpired marks (`R2TICK_REPLAY_SLOTS`) it is
  full, and further resumes get TICKET_NACK (fail closed) until marks expire.

## 2. Multiple ticket keys (rotation, clusters)

- **One key per remote. There is no multi-key or rollover window.** A ticket
  is only accepted under the key file currently configured. To rotate, replace
  the file. Every ticket still outstanding then fails AEAD and gets
  TICKET_NACK, and the client falls back to a full IKE_SA_INIT/IKE_AUTH, after
  which it receives a new ticket. No SA is lost. Expect a burst of full
  handshakes, at most one per client, after a rotation.
- **Clusters:** gateways that should accept each other's tickets (the redirect
  + resume failover in iked/ikev2_session_resume.c,
  `ike_msg_resume_store_migrate`) must load the *same* key. Their replay
  caches are only shared if the key path is on shared storage. Otherwise a
  ticket used at gateway A can be used once more at gateway B. Keep keys
  per gateway unless you need cross-gateway resume, and in that case put the
  key directory on shared storage.
- The ticket format has no version byte that older nodes can see. During a
  rolling upgrade across a format change (see NEWS 2026-10-17), tickets are
  NACKed between versions and peers fall back to a full handshake.

## 3. Clocks

- **Only the gateway's clock matters for validity.** Expiry is an absolute
  `expires_at` set from the gateway's `time()` at mint. The client is told a
  *relative* lifetime (RFC 5723 TICKET_LT_OPAQUE), which it uses only to
  decide when to stop offering the ticket. Client clock skew therefore never
  makes a ticket valid or invalid at the gateway.
- **There is no grace window.** `now >= expires_at` gets TICKET_NACK
  (`r2ticket_expired`). A resume exactly at the boundary does a full handshake.
- **Gateway wall-clock steps move expiry.** A large NTP step forward expires
  tickets early, which is harmless (full handshake). A step backward extends
  them by the size of the step. That includes certificate notAfter checks
  (`cert_due`) and replay-mark expiry. Run NTP in slew mode on gateways.
- **Clusters sharing a key** need their clocks to agree. Skew between
  gateways shifts each ticket's effective lifetime by that skew, and the
  replay marks expire by each gateway's own clock.

## Not decided / not implemented

- An overlap window for key rotation (accepting key N-1 for a while) and
  re-checking revocation (CRL/OCSP) on resume are not implemented. Both are
  policy choices; until they are made, the behaviour above is what ships.
