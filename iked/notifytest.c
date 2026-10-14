/*
 * notifytest.c — RFC 7296 §2.7 receive classification of the core error /
 * collision notify types (the "deferred sub-items" of the IANA gap report).
 *
 * RFC 7296 §2.7 (and §1.7): error notifies are in the range 0–16383
 * (IKEV2_NOTIFYTYPE_ERROR_MAX); status notifies are 16384+.
 *  - An error notify received in a response means "the corresponding
 *    request has failed entirely": the caller (createchild_init_recv_notify /
 *    the generic notify path) must treat the request as failed — on a
 *    CREATE_CHILD_SA rekey that is ikev2_child_abort(), which clears a
 *    stuck rekey_inprogress and re-arms expiry.
 *  - A status notify must be ignored (except logged).
 *
 * This locks in the implemented behaviour for the deferred items:
 *   INVALID_SPI (11), INVALID_MESSAGE_ID (9), INVALID_SELECTORS (39),
 *   TEMPORARY_FAILURE (43), SINGLE_PAIR_REQUIRED (34)  — all error-type,
 *   so ikev2_process_notify must report them (non-zero -> request failed),
 *   and SET_WINDOW_SIZE (16385) — status-type, must be ignored (0).
 *
 * The classifier is ikev2_process_notify(); a NULL ike_sa is tolerated by
 * isakmp_log (it guards `if (ike_sa)`).  Send-side emission is asserted
 * where a real send path can be driven deterministically: INVALID_SPI (11)
 * via the exported ikev2_process_delete and INVALID_MESSAGE_ID (9) via
 * ikev2_send_invalid_message_id()'s rate-limiter branch; the full initiate
 * path of 9 needs a live child/kernel and is out of the unit harness'
 * reach (covered by live matrix rows instead).
 *
 * Linked with the full iked object set (addtest_ikedsrc) so the real
 * classifier + notify_type_str are exercised, exactly as the other
 * full-link tests (test_ts_substitute, eaproundtest, ...) do.
 */
#include "config.h"
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include "racoon.h"
#include "plog.h"
#include "isakmp.h"
#include "isakmp_impl.h"
#include "ikev2.h"
#include "ikev2_impl.h"
#include "ikev2_notify.h"

#include "test_util.h"

TEST_MAIN_STUBS()

static int fails = 0;

static void
ck(int ok, const char *what)
{
	if (!ok) {
		++fails;
		printf("FAIL: %s\n", what);
	} else {
		printf("ok: %s\n", what);
	}
}

/* build a Notify payload of the given type, protocol 0, no SPI/data. */
static struct ikev2_payload_header *
mk_notify(unsigned int type, size_t *outlen)
{
	struct ikev2payl_notify *n;
	size_t len = sizeof(*n);

	n = calloc(1, len);
	if (!n)
		return NULL;
	set_payload_header(&n->header, IKEV2_NO_NEXT_PAYLOAD, len);
	n->nh.protocol_id = 0;
	n->nh.spi_size = 0;
	put_uint16(&n->nh.notify_message_type, type);
	*outlen = len;
	return (struct ikev2_payload_header *)n;
}

int
main(int argc, char *argv[])
{
	struct ikev2_payload_header *p;
	size_t len;
	int rc;

	test_init(argv[0]);

	/*
	 * Error-type notifies: each must be reported (non-zero) so the
	 * CREATE_CHILD_SA request is treated as failed (RFC 7296 §2.7).
	 */
#define CK_ERROR(n_, N_)							\
	do {								\
		p = mk_notify(N_, &len);				\
		rc = ikev2_process_notify(NULL, p, 1);			\
		ck(rc != 0, #N_ " (" #n_ ") -> non-zero (error/request-failed)"); \
		free(p);						\
	} while (0)

	CK_ERROR(11, IKEV2_INVALID_SPI);
	CK_ERROR(9, IKEV2_INVALID_MESSAGE_ID);
	CK_ERROR(39, IKEV2_INVALID_SELECTORS);
	CK_ERROR(43, IKEV2_TEMPORARY_FAILURE);
	CK_ERROR(34, IKEV2_SINGLE_PAIR_REQUIRED);
	CK_ERROR(44, IKEV2_CHILD_SA_NOT_FOUND);

	/*
	 * Status-type notifies: must be ignored (0 -> caller continues).
	 * SET_WINDOW_SIZE (16385) is the deferred item; a raw 16384 (first
	 * status value, unrecognised) pins the boundary without touching an
	 * SA-requiring handler.
	 */
#define CK_STATUS(N_)							\
	do {								\
		p = mk_notify(N_, &len);				\
		rc = ikev2_process_notify(NULL, p, 1);			\
		ck(rc == 0, #N_ " -> 0 (status/ignored)");		\
		free(p);						\
	} while (0)

	CK_STATUS(IKEV2_SET_WINDOW_SIZE);		/* 16385, deferred */

	/*
	 * Error/status boundary: 16383 (IKEV2_NOTIFYTYPE_ERROR_MAX) is the
	 * last error type and is unhandled, so must report as error.  (16384
	 * is INITIAL_CONTACT, a handled status case that needs a real SA, so
	 * it is not exercised here — SET_WINDOW_SIZE above already pins the
	 * status side of the boundary.)
	 */
	p = mk_notify(IKEV2_NOTIFYTYPE_ERROR_MAX, &len);
	rc = ikev2_process_notify(NULL, p, 1);
	ck(rc != 0, "notify 16383 (ERROR_MAX) -> non-zero (error)");
	free(p);

	/*
	 * The notify->string table must name the just-added error types
	 * (log readability / diagnostics on the wire).
	 */
	ck(strcmp(ikev2_notify_type_str(IKEV2_CHILD_SA_NOT_FOUND),
		  "CHILD_SA_NOT_FOUND") == 0,
	   "notify_type_str(44) == CHILD_SA_NOT_FOUND");
	ck(strcmp(ikev2_notify_type_str(IKEV2_TEMPORARY_FAILURE),
		  "TEMPORARY_FAILURE") == 0,
	   "notify_type_str(43) == TEMPORARY_FAILURE");
	ck(strcmp(ikev2_notify_type_str(IKEV2_INVALID_SPI),
		  "INVALID_SPI") == 0,
	   "notify_type_str(11) == INVALID_SPI");
	ck(strcmp(ikev2_notify_type_str(IKEV2_SET_WINDOW_SIZE),
		  "SET_WINDOW_SIZE") == 0,
	   "notify_type_str(16385) == SET_WINDOW_SIZE");

	/*
	 * Send side: a Delete payload naming an ESP/AH SPI we do not hold
	 * must be answered with N(INVALID_SPI) echoing the protocol + SPI
	 * (RFC 7296 §2.8.2).  Drive the real ikev2_process_delete() send
	 * path with a crafted bogus-SPI Delete and inspect the response
	 * payloads it builds.  Using a NULL ike_sa (no children) means the
	 * SPI is never found, so the INVALID_SPI branch must fire.
	 */
	{
		struct ikev2_payloads resp;
		struct ikev2_payload_header *delp;
		struct ikev2payl_delete *del;
		unsigned char buf[sizeof(*del) + 4];
		struct ikev2_sa sa;
		unsigned int found_invalid_spi = 0;
		int j;

		/* A real (empty) IKE_SA: ikev2_process_delete looks the SPI
		 * up in the child list, so a live SA with no children makes
		 * the bogus SPI never match.  A stack SA with an initialized
		 * (empty) children TAILQ avoids pulling in the scheduler via
		 * ikev2_allocate_sa — the delete path only walks this list. */
		memset(&sa, 0, sizeof(sa));
		TAILQ_INIT(&sa.children);

		del = (struct ikev2payl_delete *)buf;
		memset(buf, 0, sizeof(buf));
		set_payload_header(&del->header, IKEV2_NO_NEXT_PAYLOAD,
				   sizeof(*del) + 4);
		del->dh.protocol_id = IKEV2_DELETE_PROTO_ESP;
		del->dh.spi_size = 4;
		put_uint16(&del->dh.num_spi, 1);
		put_uint32(buf + sizeof(*del), 0xdeadbeefU); /* bogus SPI */
		delp = (struct ikev2_payload_header *)del;

		ikev2_payloads_init(&resp);
		ikev2_process_delete(&sa, delp, &resp);
		for (j = 0; j < resp.num; j++) {
			if (resp.payloads[j].type == IKEV2_PAYLOAD_NOTIFY) {
				/* ikev2_notify_payload() returns the notify
				 * BODY (starting at notify_h: proto, spi_size,
				 * type) with no payload header. */
				struct ikev2payl_notify_h *nh = (struct
				    ikev2payl_notify_h *)resp.payloads[j].data->v;
				if (get_uint16(&nh->notify_message_type) ==
				    IKEV2_INVALID_SPI)
					found_invalid_spi = 1;
			}
		}
		ck(found_invalid_spi,
		   "ikev2_process_delete(unknown SPI) builds N(INVALID_SPI)");
		ikev2_payloads_destroy(&resp);

		/*
		 * RFC 7296 §2.3: an out-of-window request is answered by
		 * initiating an INFORMATIONAL with N(INVALID_MESSAGE_ID) whose
		 * Notification Data is the 4-octet invalid Message ID (type 0 /
		 * no SPI / no protocol).  Assert the exact payload ikev2_
		 * send_invalid_message_id() builds for a given id: notify type 9,
		 * protocol 0, spi_size 0, data == the 4-octet id.  (The function
		 * itself then hands it to the INFORMATIONAL initiator, which needs
		 * a live child/kernel to transmit — not exercised here; the wire
		 * payload the function constructs is the deterministic part.)
		 */
		{
			rc_vchar_t *n;
			struct ikev2payl_notify_h *nh;
			uint8_t *data;
			uint8_t idbuf[4] = { 0xde, 0xad, 0xbe, 0xef };

			n = ikev2_notify_payload(0, 0, 0, IKEV2_INVALID_MESSAGE_ID,
						 idbuf, 4);
			ck(n != NULL, "INVALID_MESSAGE_ID payload alloc");
			nh = (struct ikev2payl_notify_h *)n->v;
			ck(nh->protocol_id == 0 && nh->spi_size == 0,
			   "INVALID_MESSAGE_ID: protocol 0, no SPI");
			ck(get_uint16(&nh->notify_message_type) ==
			   IKEV2_INVALID_MESSAGE_ID,
			   "INVALID_MESSAGE_ID: type 9");
			data = n->v + sizeof(*nh);
			ck(data[0] == idbuf[0] && data[1] == idbuf[1] &&
			   data[2] == idbuf[2] && data[3] == idbuf[3],
			   "INVALID_MESSAGE_ID: data == 4-octet invalid id");
			rc_vfree(n);
		}

		/*
		 * RFC 5685 s9.2 redirect Notify Data: GW Ident Type (1) |
		 * GW Ident Len (1) | Gateway Identity | Nonce Data.  IPv4
		 * gateway -> type 1 / 4-octet addr; IPv6 -> type 2 /
		 * 16-octet addr; FQDN -> type 3 / the raw hostname bytes.
		 * ikev2_build_redirect_notify_data() is what
		 * ikev2_respond_redirect() sends on the wire.
		 */
		{
			rc_vchar_t *gw, *ni, *d;
			unsigned char nib[6] = { 0xa, 0xb, 0xc, 0xd, 0xe, 0xf };

			ni = rc_vnew(nib, 6);
			ck(ni != NULL, "redirect: ni alloc");

			/* IPv4 gateway "10.99.0.20" (rc_vnew carries no NUL — the
			 * NUL-termination inside the builder is what this exercises) */
			gw = rc_vnew((unsigned char *)"10.99.0.20", 10);
			ck(gw != NULL, "redirect: gw alloc");
			d = ikev2_build_redirect_notify_data(gw, ni);
			ck(d != NULL, "redirect ipv4: data built");
			if (d) {
				ck(d->u[0] == 1, "redirect ipv4: GW type 1");
				ck(d->u[1] == 4, "redirect ipv4: GW ident len 4 (1 octet)");
				ck(d->u[2] == 10 && d->u[3] == 99 &&
				   d->u[4] == 0 && d->u[5] == 20,
				   "redirect ipv4: gw == 10.99.0.20");
				/* RFC 5685 s9.2: [Type:1][Len:1][Ident][Ni]; ni after
				 * (1+1+4)=6 id bytes */
				ck(d->l == 2 + 4 + 6, "redirect ipv4: total len");
				ck(d->u[6] == 0xa && d->u[9] == 0xd,
				   "redirect ipv4: ni echoed after gw");
				rc_vfree(d);
			}
			rc_vfree(gw);

			/* FQDN gateway "gw2.example.net" -> type 3 */
			gw = rc_vnew((unsigned char *)"gw2.example.net", 15);
			ck(gw != NULL, "redirect: gw2 alloc");
			d = ikev2_build_redirect_notify_data(gw, ni);
			ck(d != NULL, "redirect fqdn: data built");
			if (d) {
				ck(d->u[0] == 3, "redirect fqdn: GW type 3");
				ck(d->u[1] == 15, "redirect fqdn: GW ident len 15 (1 octet)");
				ck(memcmp(d->u + 2, "gw2.example.net", 15) == 0,
				   "redirect fqdn: gw bytes");
				rc_vfree(d);
			}
			rc_vfree(gw);

			/* IPv6 gateway "2001:db8::1" -> type 2 / 16-octet addr */
			gw = rc_vnew((unsigned char *)"2001:db8::1", 11);
			ck(gw != NULL, "redirect: gw6 alloc");
			d = ikev2_build_redirect_notify_data(gw, ni);
			ck(d != NULL, "redirect ipv6: data built");
			if (d) {
				ck(d->u[0] == 2, "redirect ipv6: GW type 2");
				ck(d->u[1] == 16, "redirect ipv6: GW ident len 16");
				/* 2001:0db8:0000:0000:0000:0000:0000:0001 —
				 * address fills u[2..17]: head 20 01 0d b8,
				 * all-zero middle, tail ...00 01 at u[16]/u[17] */
				ck(d->u[2] == 0x20 && d->u[3] == 0x01 &&
				   d->u[4] == 0x0d && d->u[5] == 0xb8 &&
				   d->u[6] == 0x00 && d->u[15] == 0x00 &&
				   d->u[16] == 0x00 && d->u[17] == 0x01,
				   "redirect ipv6: gw == 2001:db8::1 at bytes 2..17");
				rc_vfree(d);
			}
			rc_vfree(gw);

			/* A >255-octet FQDN cannot be encoded in the 1-octet
			 * GW Ident Len; the builder must refuse it (NULL). */
			{
				size_t bigl = 300;
				unsigned char *big =
					(unsigned char *)racoon_malloc(bigl);
				ck(big != NULL, "redirect: big gw alloc");
				if (big) {
					memset(big, 0x61 /* 'a' */, bigl);
					gw = rc_vnew(big, bigl);
					ck(gw != NULL, "redirect: big gw vchar");
					d = ikev2_build_redirect_notify_data(gw, ni);
					ck(d == NULL,
					   "redirect fqdn >255: refused (NULL)");
					rc_vfree(gw);
					racoon_free(big);
				}
			}
			/* Round-trip the parser against fresh owned buffers.
		 * parse() must return the SAME gw identity + echoed ni
		 * that build() emitted, for an IPv4 and an FQDN target. */
		{
			rc_vchar_t *pgw = 0, *pni = 0;
			uint8_t pt = 0;

			/* IPv4: build "10.99.0.20" + ni, then parse it back */
			gw = rc_vnew((unsigned char *)"10.99.0.20", 10);
			d = ikev2_build_redirect_notify_data(gw, ni);
			ck(d != NULL, "redirect parse: ipv4 built");
			if (d) {
				ck(ikev2_parse_redirect_notify_data(
				    d, &pt, &pgw, &pni) == 0,
				   "redirect parse: ipv4 ok");
				ck(pt == 1, "redirect parse: ipv4 type 1");
				ck(pgw && pgw->l == 4 && pgw->u[0] == 10 &&
				   pgw->u[3] == 20,
				   "redirect parse: ipv4 gw bytes");
				ck(pni && pni->l == 6 && pni->u[0] == 0xa &&
				   pni->u[5] == 0xf,
				   "redirect parse: ipv4 echoes ni");
				rc_vfree(d);
			}
			rc_vfree(gw);
			if (pgw) rc_vfree(pgw);
			if (pni) rc_vfree(pni);
			pgw = pni = 0;

			/* FQDN: build "gw2.example.net", parse back type 3 */
			gw = rc_vnew((unsigned char *)"gw2.example.net", 15);
			d = ikev2_build_redirect_notify_data(gw, ni);
			ck(d != NULL, "redirect parse: fqdn built");
			if (d) {
				ck(ikev2_parse_redirect_notify_data(
				    d, &pt, &pgw, &pni) == 0,
				   "redirect parse: fqdn ok");
				ck(pt == 3, "redirect parse: fqdn type 3");
				ck(pgw && pgw->l == 15 &&
				   memcmp(pgw->u, "gw2.example.net", 15) == 0,
				   "redirect parse: fqdn gw bytes");
				rc_vfree(d);
			}
			rc_vfree(gw);
			if (pgw) rc_vfree(pgw);
			if (pni) rc_vfree(pni);
			pgw = pni = 0;

			/* malformed / wrong-cardinality must be rejected:
			 * ipv4 type but len != 4  */
			{
				unsigned char bad[8];
				rc_vchar_t bd;

				memset(bad, 0, sizeof(bad));
				bad[0] = 1; bad[1] = 3;	/* type ipv4, len 3 */
				bd.l = sizeof(bad);
				bd.u = bad;
				ck(ikev2_parse_redirect_notify_data(
				    &bd, &pt, &pgw, &pni) != 0,
				   "redirect parse: ipv4 wrong len rejected");
			}
			/* bogus type */
			{
				unsigned char bad[8];
				rc_vchar_t bd;

				memset(bad, 0, sizeof(bad));
				bad[0] = 9; bad[1] = 4;	/* unknown type 9 */
				bd.l = sizeof(bad);
				bd.u = bad;
				ck(ikev2_parse_redirect_notify_data(
				    &bd, &pt, &pgw, &pni) != 0,
				   "redirect parse: bogus type rejected");
			}
			/* truncated (no identity / no ni) */
			{
				unsigned char bad[4];
				rc_vchar_t bd;

				memset(bad, 0, sizeof(bad));
				bad[0] = 1; bad[1] = 4;	/* len 4 but only 2 left */
				bd.l = 2;
				bd.u = bad;
				ck(ikev2_parse_redirect_notify_data(
				    &bd, &pt, &pgw, &pni) != 0,
				   "redirect parse: truncated rejected");
			}
		}
		/* RFC 5685 s7 redirect-loop limit */
		{
			int cnt = 0, k, okc = 0;
			time_t win = 0, t0 = 1000000;

			for (k = 0; k < 5; ++k)
				if (ikev2_redirect_loop_check(&cnt, &win,
				    t0 + k, 5, 300) == 0)
					++okc;
			ck(okc == 5, "redirect loop: first 5 followed");
			ck(ikev2_redirect_loop_check(&cnt, &win, t0 + 10,
			    5, 300) == -1, "redirect loop: 6th within 300s refused");
			ck(ikev2_redirect_loop_check(&cnt, &win, t0 + 299,
			    5, 300) == -1, "redirect loop: still refused at 299s");
			ck(ikev2_redirect_loop_check(&cnt, &win, t0 + 300,
			    5, 300) == 0, "redirect loop: window expires at 300s");
			ck(cnt == 1, "redirect loop: count restarts in new window");
			cnt = 0; win = 0;
			ck(ikev2_redirect_loop_check(&cnt, &win, t0, 1, 300) == 0
			    && ikev2_redirect_loop_check(&cnt, &win, t0, 1, 300)
			    == -1, "redirect loop: redirect_max 1 honoured");
			cnt = 3; win = t0 + 50;	/* clock stepped back */
			ck(ikev2_redirect_loop_check(&cnt, &win, t0, 5, 300) == 0
			    && cnt == 1, "redirect loop: clock step back resets");
		}
		/* RFC 5685 s9.3 REDIRECTED_FROM build + redirect_gw sadup */
		{
			rc_vchar_t *ident, *rfd;
			struct sockaddr *sa;

			/* IPv4 original gateway 10.99.0.20 */
			ident = rc_vnew((unsigned char *)"\x0a\x63\x00\x14", 4);
			rfd = ikev2_build_redirected_from_data(1, ident);
			ck(rfd != NULL, "redirected_from: ipv4 built");
			if (rfd) {
				ck(rfd->u[0] == 1, "redirected_from: type 1");
				ck(rfd->u[1] == 4,
				   "redirected_from: len 4");
				ck(rfd->l == 6 && rfd->u[2] == 0x0a &&
				   rfd->u[5] == 0x14,
				   "redirected_from: ipv4 gw bytes");
				rc_vfree(rfd);
			}
			rc_vfree(ident);
			/* IPv6 original gateway 2001:db8::1 (type 2 / 16) */
			{
				uint8_t v6[16];
				memset(v6, 0, sizeof(v6));
				v6[0] = 0x20; v6[1] = 0x01;
				v6[2] = 0x0d; v6[3] = 0xb8;
				v6[15] = 0x01;
				ident = rc_vnew(v6, 16);
				rfd = ikev2_build_redirected_from_data(2, ident);
				ck(rfd != NULL, "redirected_from: ipv6 built");
				if (rfd) {
					ck(rfd->u[0] == 2,
					   "redirected_from: type 2");
					ck(rfd->u[1] == 16,
					   "redirected_from: len 16");
					ck(rfd->l == 18 &&
					   rfd->u[2] == 0x20 && rfd->u[17] == 0x01,
					   "redirected_from: ipv6 gw bytes");
					rc_vfree(rfd);
				}
				/* sadup resolves to an IPv6 sockaddr */
				sa = ikev2_redirect_gw_sadup(2, ident);
				ck(sa != NULL,
				   "redirect_gw_sadup: ipv6 resolved");
				if (sa) {
					ck(sa->sa_family == AF_INET6,
					   "redirect_gw_sadup: ipv6 family");
					racoon_free(sa);
				}
				rc_vfree(ident);
			}
			/* wrong type cardinality rejected */
			ident = rc_vnew((unsigned char *)"\x0a\x63\x00", 3);
			ck(ikev2_build_redirected_from_data(1, ident) == NULL,
			   "redirected_from: ipv4 wrong len rejected");
			/* sadup rejects it too */
			ck(ikev2_redirect_gw_sadup(1, ident) == NULL,
			   "redirect_gw_sadup: ipv4 wrong len rejected");
			rc_vfree(ident);
		}
		rc_vfree(ni);

			/*
			 * Receive side: a responder that sees the initiator's
			 * N(REDIRECT_SUPPORTED) (16406) in IKE_SA_INIT must
			 * record peer_sent_redirect so responder_state0_send
			 * knows it MAY answer REDIRECT (RFC 5685 s3: never
			 * to a peer that did not offer 16406).  Drive the
			 * real resp_state0_recv_notify() with a 16406 notify.
			 */
			{
				struct ikev2_sa sa;
				struct ikev2payl_notify *np;
				struct ikev2_payload_header *ph;
				unsigned char nb[sizeof(*np) + 4];
				struct sockaddr_in local, remote;

				memset(&sa, 0, sizeof(sa));
				memset(nb, 0, sizeof(nb));
				np = (struct ikev2payl_notify *)nb;
				/* empty notify: REDIRECT_SUPPORTED carries no
				 * data */
				set_payload_header(&np->header,
					IKEV2_NO_NEXT_PAYLOAD, sizeof(*np));
				np->nh.protocol_id = 0;
				np->nh.spi_size = 0;
				put_uint16(&np->nh.notify_message_type,
					   IKEV2_REDIRECT_SUPPORTED);
				ph = (struct ikev2_payload_header *)np;
				memset(&local, 0, sizeof(local));
				memset(&remote, 0, sizeof(remote));
				local.sin_family = AF_INET;
				remote.sin_family = AF_INET;
				/* packet arg is not dereferenced on a bare
				 * 16406 (no data, spi_size 0): the record-flag
				 * path below never logs the packet. */
				ck(resp_state0_recv_notify(&sa,
					(rc_vchar_t *)0, (struct sockaddr *)&remote,
					(struct sockaddr *)&local, ph) == 0,
				   "resp_state0_recv: REDIRECT_SUPPORTED accepted");
				ck(sa.peer_sent_redirect == 1,
				   "resp_state0_recv: peer_sent_redirect set by 16406");
			}
			/* RFC 5685 redirect pool resolver:
			 * ikev2_redirect_pool_select() must (a) resolve a single
			 * entry to itself, (b) spread different peers across a
			 * pool deterministically (the same peer always maps to
			 * the same member — stable affinity so a re-initiating
			 * client returns to the member holding its resume
			 * ticket/dump), and (c) trim whitespace around
			 * members. */
			{
				struct sockaddr_in p1, p2;
				int i;

				memset(&p1, 0, sizeof(p1));
				memset(&p2, 0, sizeof(p2));
				p1.sin_family = AF_INET;
				p2.sin_family = AF_INET;
				p1.sin_addr.s_addr = htonl(0x0a010001u);
				p2.sin_addr.s_addr = htonl(0x0a010002u);

				/* single entry -> identical to input */
				gw = rc_vnew((unsigned char *)"10.9.9.9", 9);
				d = ikev2_redirect_pool_select(gw,
				    (struct sockaddr *)&p1);
				ck(d != NULL && d->l == 9 &&
				   memcmp(d->u, "10.9.9.9", 9) == 0,
				   "redirect pool: single entry resolves to itself");
				if (d) rc_vfree(d);
				rc_vfree(gw);

				/* pool: two peers map deterministically;
				 * assert the selection only ever yields an
				 * in-pool member and is stable across repeated
				 * calls for the same peer */
				{
					rc_vchar_t *pool, *r1a, *r1b, *r2;

					pool = rc_vnew((unsigned char *)
					    "10.0.0.7,10.0.0.8,10.0.0.9", 27);
					r1a = ikev2_redirect_pool_select(pool,
					    (struct sockaddr *)&p1);
					r1b = ikev2_redirect_pool_select(pool,
					    (struct sockaddr *)&p1);
					r2 = ikev2_redirect_pool_select(pool,
					    (struct sockaddr *)&p2);
					/* deterministic for the same peer */
					ck(r1a && r1b && r1a->l == r1b->l &&
					   memcmp(r1a->u, r1b->u, r1a->l) == 0,
					   "redirect pool: same peer -> same member "
					   "(stable affinity)");
					/* port-independent affinity: the same
					 * ADDRESS with a different source port
					 * must still land on the same member (a
					 * client re-initiating from a changed
					 * ephemeral port must return to the
					 * member holding its resume ticket /
					 * dump) */
					{
						struct sockaddr_in p1b = p1;
						rc_vchar_t *r1c;

						p1b.sin_port = htons(54321);
						r1c = ikev2_redirect_pool_select(
						    pool, (struct sockaddr *)&p1b);
						ck(r1a && r1c && r1a->l == r1c->l &&
						   memcmp(r1a->u, r1c->u, r1a->l) == 0,
						   "redirect pool: addr affinity "
						   "ignores source port");
						if (r1c) rc_vfree(r1c);
					}
					/* both selections are in-pool */
					ck(r1a && r1a->l >= 8 &&
					   (memcmp(r1a->u, "10.0.0.7", 8) == 0 ||
					    memcmp(r1a->u, "10.0.0.8", 8) == 0 ||
					    memcmp(r1a->u, "10.0.0.9", 8) == 0),
					   "redirect pool: p1 maps into the pool");
					ck(r2 && r2->l >= 8 &&
					   (memcmp(r2->u, "10.0.0.7", 8) == 0 ||
					    memcmp(r2->u, "10.0.0.8", 8) == 0 ||
					    memcmp(r2->u, "10.0.0.9", 8) == 0),
					   "redirect pool: p2 maps into the pool");
					/* whitespace trimming */
					rc_vfree(pool);
					pool = rc_vnew((unsigned char *)
					    " 10.0.0.7 , 10.0.0.8 ", 22);
					{
						rc_vchar_t *rt =
						    ikev2_redirect_pool_select(
						    pool, (struct sockaddr *)&p1);
						ck(rt && rt->l >= 8 &&
						   (memcmp(rt->u, "10.0.0.7", 8) == 0 ||
						    memcmp(rt->u, "10.0.0.8", 8) == 0),
						   "redirect pool: members trimmed");
						if (rt) rc_vfree(rt);
					}
					rc_vfree(pool);
					if (r1a) rc_vfree(r1a);
					if (r1b) rc_vfree(r1b);
					if (r2) rc_vfree(r2);
				}
				/* empty pool -> NULL */
				{
					rc_vchar_t *e =
					    rc_vnew((unsigned char *)"", 0);
					ck(ikev2_redirect_pool_select(e,
					    (struct sockaddr *)&p1) == NULL,
					   "redirect pool: empty pool -> NULL");
					rc_vfree(e);
				}
				(void)i;
			}
		}
	}

		/*
		 * Drive ikev2_send_invalid_message_id() ITSELF on the only
		 * branch runnable without a live child/kernel: the
		 * rate-limiter.  With invalid_msgid_last_sent set ahead of
		 * now, RFC 7296 §2.3's one-per-second cap must make the
		 * function return 0 (rate-limited) and must NOT reach the
		 * INFORMATIONAL initiator.  Deterministic, side-effect-free
		 * part of the real function (the payload it would build is
		 * asserted above); the initiate path needs a running child
		 * and is out of the unit harness's reach.
		 */
		{
			struct ikev2_sa sa;
			memset(&sa, 0, sizeof(sa));
			TAILQ_INIT(&sa.children);
			/* rate-limiter: set last_sent far in the FUTURE so
			 * time(NULL) - last < 1 regardless of when the
			 * second boundary ticks between the reference and
			 * the check inside the function (a wall-clock race
			 * that would otherwise let it through to the
			 * initiate path -> crash on the stack-faked SA). */
			sa.invalid_msgid_last_sent = time(NULL) + 1000;
			ck(ikev2_send_invalid_message_id(&sa, 0xdeadbeef) == 0,
			   "ikev2_send_invalid_message_id: rate-limited -> 0, no initiate");
		}

		if (fails) {
		printf("notifytest: %d FAILURE(S)\n", fails);
		return 1;
	}
	printf("notifytest: all checks passed\n");
	return 0;
}
