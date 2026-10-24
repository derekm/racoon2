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
#include "ikev2_drain.h"
#include "ike_conf.h"
#include <sys/time.h>

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
					/* whitespace trimming: exact bytes, no
					 * trailing padding.  rc_vnew() with an
					 * explicit length that includes a NUL (as a
					 * config string might) must still trim to
					 * exactly the member bytes. */
					rc_vfree(pool);
					pool = rc_vnew((unsigned char *)
					    " 10.0.0.7 , 10.0.0.8 ", 22);
					{
						rc_vchar_t *rt =
						    ikev2_redirect_pool_select(
						    pool, (struct sockaddr *)&p1);
						ck(rt && rt->l == 8 &&
						   (memcmp(rt->u, "10.0.0.7", 8) == 0 ||
						    memcmp(rt->u, "10.0.0.8", 8) == 0),
						   "redirect pool: members trimmed to "
						   "exact bytes");
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
				/* IPv6 + padding: the resolver must hash
				 * ONLY the address bytes (family + addr), so a
				 * changed source port, sin6_flowinfo, or
				 * scope id must NOT move the member (a
				 * returning client must land on the member
				 * holding its resume ticket/dump). */
				{
					rc_vchar_t *pool, *r6a, *r6b, *r6c;
					struct sockaddr_in6 v6a, v6b, v6c;

					memset(&v6a, 0, sizeof(v6a));
					memset(&v6b, 0, sizeof(v6b));
					memset(&v6c, 0, sizeof(v6c));
					v6a.sin6_family = AF_INET6;
					v6a.sin6_addr.s6_addr[15] = 1;
					v6b = v6a;
					v6b.sin6_port = htons(54321);
					v6c = v6a;
					v6c.sin6_flowinfo = 0x80001;
					v6c.sin6_scope_id = 42;

					pool = rc_vnew((unsigned char *)
					    "2001:db8::7,2001:db8::8", 23);
					r6a = ikev2_redirect_pool_select(pool,
					    (struct sockaddr *)&v6a);
					r6b = ikev2_redirect_pool_select(pool,
					    (struct sockaddr *)&v6b);
					r6c = ikev2_redirect_pool_select(pool,
					    (struct sockaddr *)&v6c);
					ck(r6a && r6b && r6c &&
					   r6a->l == r6b->l &&
					   r6a->l == r6c->l &&
					   memcmp(r6a->u, r6b->u, r6a->l) == 0 &&
					   memcmp(r6a->u, r6c->u, r6a->l) == 0,
					   "redirect pool: IPv6 addr affinity "
					   "ignores port/flowinfo/scope");
					if (r6a) rc_vfree(r6a);
					if (r6b) rc_vfree(r6b);
					if (r6c) rc_vfree(r6c);
					rc_vfree(pool);
				}
				/* port sweep: several distinct source ports
				 * on the same address must all map to the same
				 * member (the reviewer's multi-port concern). */
				{
					rc_vchar_t *pool, *ref, *pn;
					struct sockaddr_in pp;
					int port;

					pool = rc_vnew((unsigned char *)
					    "10.0.0.7,10.0.0.8,10.0.0.9", 27);
					pp = p1;
					ref = ikev2_redirect_pool_select(pool,
					    (struct sockaddr *)&pp);
					for (port = 0; port < 8; port++) {
						pp.sin_port = htons(
						    (unsigned short)(10000 +
						    port));
						pn = ikev2_redirect_pool_select(
						    pool, (struct sockaddr *)&pp);
						ck(ref && pn && ref->l == pn->l &&
						   memcmp(ref->u, pn->u, ref->l) == 0,
						   "redirect pool: port sweep "
						   "stays on same member");
						if (pn) rc_vfree(pn);
					}
					if (ref) rc_vfree(ref);
					rc_vfree(pool);
				}
				(void)i;
			}
		}

		/* RFC 5685 drain table (ikedctl drain-sa): set a drain
		 * redirect target per peer, look it back up, and clear. */
		{
			struct sockaddr_in dp1, dp2;

			memset(&dp1, 0, sizeof(dp1));
			memset(&dp2, 0, sizeof(dp2));
			dp1.sin_family = AF_INET;
			dp2.sin_family = AF_INET;
			dp1.sin_addr.s_addr = htonl(0x0a0100c8u); /* 10.1.0.200 */
			dp2.sin_addr.s_addr = htonl(0x0a0100c9u); /* 10.1.0.201 */

			ikev2_drain_clear_all();
			ck(ikev2_drain_lookup((struct sockaddr *)&dp1) == NULL,
			   "drain: empty table -> no target");

			ck(ikev2_drain_set((struct sockaddr *)&dp1,
			    "10.0.0.7") == 0,
			   "drain: set target for peer1");
			{
				const char *t = ikev2_drain_lookup(
				    (struct sockaddr *)&dp1);
				ck(t && strcmp(t, "10.0.0.7") == 0,
				   "drain: lookup returns the set target");
			}
			/* peer2 unaffected */
			ck(ikev2_drain_lookup((struct sockaddr *)&dp2) == NULL,
			   "drain: peer2 untouched");
			/* overwrite in place */
			ck(ikev2_drain_set((struct sockaddr *)&dp1,
			    "10.0.0.8") == 0,
			   "drain: overwrite peer1 target");
			{
				const char *t = ikev2_drain_lookup(
				    (struct sockaddr *)&dp1);
				ck(t && strcmp(t, "10.0.0.8") == 0,
				   "drain: overwrite takes effect");
			}
			/* clear (NULL gw) removes */
			ck(ikev2_drain_set((struct sockaddr *)&dp1, NULL) == 0,
			   "drain: clear peer1");
			ck(ikev2_drain_lookup((struct sockaddr *)&dp1) == NULL,
			   "drain: cleared target gone");
			/* NULL/invalid peer rejected */
			ck(ikev2_drain_set(NULL, "10.0.0.7") == -1,
			   "drain: NULL peer rejected");
			{
				struct sockaddr_in badp;
				memset(&badp, 0, sizeof(badp));
				badp.sin_family = AF_UNIX;
				ck(ikev2_drain_set((struct sockaddr *)&badp,
				    "10.0.0.7") == -1,
				   "drain: unknown family rejected");
			}
			ikev2_drain_clear_all();
			ck(ikev2_drain_lookup((struct sockaddr *)&dp1) == NULL,
			   "drain: clear_all empties the table");
			/* REVIEWER BLOCKER: the drain key is per-ADDRESS
			 * (family + IP), NOT port.  ikedctl drain-sa builds
			 * the peer via fill_index with source PORT 0, but the
			 * responder looks up the packet's real source sockaddr
			 * (port 500/4500/ephemeral, never 0).  A full-sockaddr
			 * match would make every CLI-set drain inert.  So a
			 * port-0-set drain MUST be found by a real-port lookup,
			 * IPv4 and IPv6. */
			{
				struct sockaddr_in realp;
				struct sockaddr_in6 d6, real6;

				memset(&realp, 0, sizeof(realp));
				realp.sin_family = AF_INET;
				realp.sin_addr.s_addr = dp1.sin_addr.s_addr;
				realp.sin_port = htons(4500); /* real src */
				ck(ikev2_drain_set((struct sockaddr *)&dp1,
				    "10.0.0.7") == 0, /* CLI: port 0 */
				   "drain: port-0 set succeeds (IPv4)");
				{
					const char *r =
					    ikev2_drain_lookup(
					    (struct sockaddr *)&realp);
					ck(r && strcmp(r, "10.0.0.7") == 0,
					   "drain: port-0 set matches real-port "
					   "lookup returning gateway (IPv4)");
				}

				memset(&d6, 0, sizeof(d6));
				d6.sin6_family = AF_INET6;
				d6.sin6_addr.s6_addr[15] = 7;
				ck(ikev2_drain_set((struct sockaddr *)&d6,
				    "2001:db8::9") == 0, /* CLI: port 0 */
				   "drain: port-0 set succeeds (IPv6)");
				memset(&real6, 0, sizeof(real6));
				real6.sin6_family = AF_INET6;
				real6.sin6_addr.s6_addr[15] = 7;
				real6.sin6_port = htons(500); /* real src */
				{
					const char *r =
					    ikev2_drain_lookup(
					    (struct sockaddr *)&real6);
					ck(r && strcmp(r, "2001:db8::9") == 0,
					   "drain: port-0 set matches real-port "
					   "lookup returning gateway (IPv6)");
				}
				/* different addr, real port: NOT a match */
				realp.sin_addr.s_addr = htonl(0x0a0100c9u);
				ck(ikev2_drain_lookup((struct sockaddr *)&realp)
				    == NULL,
				   "drain: different addr does not match");
				/* different IPv6 addr: NOT a match */
				real6.sin6_addr.s6_addr[15] = 8;
				ck(ikev2_drain_lookup((struct sockaddr *)&real6)
				    == NULL,
				   "drain: different IPv6 addr does not match");
			}
			ikev2_drain_clear_all();
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

		/*
	 * RFC 4739 multiple authentication + RFC 4478 AUTH_LIFETIME.
	 * Both default off: with multiple_auth off neither 16404 nor 16405
	 * changes SA state; AUTH_LIFETIME is parsed strictly (4 octets) and
	 * caps the SA only for an initiator with honor_auth_lifetime on.
	 */
	{
		struct rcf_kmp ikm;
		struct rcf_remote rm;
		struct ikev2_sa sa;
		struct timeval now;
		uint32_t secs;

		memset(&ikm, 0, sizeof(ikm));
		memset(&rm, 0, sizeof(rm));
		rm.ikev2 = &ikm;
		memset(&sa, 0, sizeof(sa));
		sa.rmconf = &rm;

		/* off (explicit) */
		ikm.multiple_auth = RCT_BOOL_OFF;
		p = mk_notify(IKEV2_MULTIPLE_AUTH_SUPPORTED, &len);
		ck(ikev2_process_notify(&sa, p, 1) == 0 && !sa.peer_multi_auth,
		   "16404 ignored with multiple_auth off");
		free(p);
		p = mk_notify(IKEV2_ANOTHER_AUTH_FOLLOWS, &len);
		ck(ikev2_process_notify(&sa, p, 1) == 0 && !sa.peer_another_auth,
		   "16405 ignored with multiple_auth off");
		free(p);
		/* on, but unauthenticated: ignored */
		ikm.multiple_auth = RCT_BOOL_ON;
		p = mk_notify(IKEV2_ANOTHER_AUTH_FOLLOWS, &len);
		ck(ikev2_process_notify(&sa, p, 0) == 0 && !sa.peer_another_auth,
		   "16405 ignored when not cryptographically protected");
		free(p);
		/* on + protected */
		p = mk_notify(IKEV2_MULTIPLE_AUTH_SUPPORTED, &len);
		ck(ikev2_process_notify(&sa, p, 1) == 0 && sa.peer_multi_auth == 1,
		   "16404 recorded with multiple_auth on");
		free(p);
		p = mk_notify(IKEV2_ANOTHER_AUTH_FOLLOWS, &len);
		ck(ikev2_process_notify(&sa, p, 1) == 0 && sa.peer_another_auth == 1,
		   "16405 recorded with multiple_auth on");
		free(p);
		ck(strcmp(ikev2_notify_type_str(IKEV2_MULTIPLE_AUTH_SUPPORTED),
		   "MULTIPLE_AUTH_SUPPORTED") == 0, "16404 named");
		ck(strcmp(ikev2_notify_type_str(IKEV2_ANOTHER_AUTH_FOLLOWS),
		   "ANOTHER_AUTH_FOLLOWS") == 0, "16405 named");

		/* decision table */
		ck(ikev2_multi_auth_decide(1, 0, 1, 0) == IKEV2_MA_SINGLE,
		   "decide: no ANOTHER_AUTH_FOLLOWS -> single round");
		ck(ikev2_multi_auth_decide(0, 0, 0, 0) == IKEV2_MA_SINGLE,
		   "decide: off, nothing flagged -> single round");
		ck(ikev2_multi_auth_decide(1, 1, 1, 0) == IKEV2_MA_SECOND_ROUND,
		   "decide: on + flagged + eap -> second round");
		ck(ikev2_multi_auth_decide(1, 1, 0, 0) == IKEV2_MA_REFUSE,
		   "decide: flagged but no EAP second method -> refuse");
		ck(ikev2_multi_auth_decide(0, 1, 1, 0) == IKEV2_MA_REFUSE,
		   "decide: flagged while off -> refuse");
		ck(ikev2_multi_auth_decide(1, 1, 1, 1) == IKEV2_MA_REFUSE,
		   "decide: a third round -> refuse");

		/* initiator plan (cfg_on, peer_supported, has_second) */
		ck(ikev2_multi_auth_plan(0, 1, 1) == IKEV2_MAI_SINGLE,
		   "plan: option off -> single round even with a second id");
		ck(ikev2_multi_auth_plan(1, 1, 0) == IKEV2_MAI_SINGLE,
		   "plan: on, no second id -> single round");
		ck(ikev2_multi_auth_plan(1, 1, 1) == IKEV2_MAI_TWO_ROUNDS,
		   "plan: on + second id + peer support -> two rounds");
		ck(ikev2_multi_auth_plan(1, 0, 1) == IKEV2_MAI_REFUSE,
		   "plan: second id but peer lacks support -> refuse");
		ck(ikev2_multi_auth_plan(0, 0, 0) == IKEV2_MAI_SINGLE,
		   "plan: all off -> single round");

		/* AUTH_LIFETIME parse: exactly 4 octets */
		{
			size_t dl;
			for (dl = 0; dl <= 6; dl++) {
				struct ikev2payl_notify *n;
				size_t l = sizeof(*n) + dl;
				char what[80];

				n = calloc(1, l);
				set_payload_header(&n->header, IKEV2_NO_NEXT_PAYLOAD, l);
				put_uint16(&n->nh.notify_message_type,
				    IKEV2_AUTH_LIFETIME);
				if (dl >= 4) {
					uint8_t *d = (uint8_t *)(n + 1);
					d[0] = 0; d[1] = 0; d[2] = 0x0e; d[3] = 0x10;
				}
				secs = 0;
				rc = ikev2_auth_lifetime_parse(n, &secs);
				snprintf(what, sizeof(what),
				    "AUTH_LIFETIME %zu-octet data %s", dl,
				    dl == 4 ? "-> 3600" : "rejected");
				ck(dl == 4 ? (rc == 0 && secs == 3600) : rc != 0,
				   what);
				free(n);
			}
		}

		/* AUTH_LIFETIME action */
		{
			struct ikev2payl_notify *n;
			size_t l = sizeof(*n) + 4;
			uint8_t *d;

			n = calloc(1, l);
			set_payload_header(&n->header, IKEV2_NO_NEXT_PAYLOAD, l);
			put_uint16(&n->nh.notify_message_type, IKEV2_AUTH_LIFETIME);
			d = (uint8_t *)(n + 1);
			d[0] = 0; d[1] = 0; d[2] = 0x0e; d[3] = 0x10;	/* 3600 */

			sa.is_initiator = 1;
			ikm.honor_auth_lifetime = RCT_BOOL_OFF;
			ck(ikev2_process_notify(&sa, (void *)n, 1) == 0 &&
			   sa.auth_due.tv_sec == 0,
			   "AUTH_LIFETIME not honoured with honor_auth_lifetime off");
			ikm.honor_auth_lifetime = RCT_BOOL_ON;
			sa.is_initiator = 0;
			ck(ikev2_process_notify(&sa, (void *)n, 1) == 0 &&
			   sa.auth_due.tv_sec == 0,
			   "AUTH_LIFETIME ignored by a responder");
			sa.is_initiator = 1;
			ck(ikev2_process_notify(&sa, (void *)n, 0) == 0 &&
			   sa.auth_due.tv_sec == 0,
			   "AUTH_LIFETIME ignored when unprotected");
			gettimeofday(&now, 0);
			ck(ikev2_process_notify(&sa, (void *)n, 1) == 0 &&
			   sa.auth_due.tv_sec >= now.tv_sec + 3599 &&
			   sa.auth_due.tv_sec <= now.tv_sec + 3601,
			   "AUTH_LIFETIME 3600 caps the initiator SA at now+3600");
			d[2] = 0; d[3] = 60;
			ck(ikev2_process_notify(&sa, (void *)n, 1) == 0 &&
			   sa.auth_due.tv_sec <= now.tv_sec + 61,
			   "a shorter AUTH_LIFETIME lowers the cap");
			d[2] = 0x0e; d[3] = 0x10;
			ck(ikev2_process_notify(&sa, (void *)n, 1) == 0 &&
			   sa.auth_due.tv_sec <= now.tv_sec + 61,
			   "a longer AUTH_LIFETIME never extends the cap");
			free(n);
		}

		/* responder emission */
		{
			struct ikev2_payloads pl;
			struct ikev2_payload_info *e;
			int nn = 0, ok = 0;

			ikev2_payloads_init(&pl);
			ikm.auth_lifetime = 0;
			ikev2_push_auth_lifetime(&sa, &pl);
			ck(pl.num == 0, "no AUTH_LIFETIME pushed when unset");
			ikev2_payloads_destroy(&pl);

			ikev2_payloads_init(&pl);
			ikm.auth_lifetime = 7200;
			ikev2_push_auth_lifetime(&sa, &pl);
			for (nn = 0; nn < pl.num; nn++) {
				e = &pl.payloads[nn];
				if (e->type == IKEV2_PAYLOAD_NOTIFY && e->data &&
				    e->data->l == sizeof(struct ikev2payl_notify_h) + 4) {
					struct ikev2payl_notify_h *h =
					    (struct ikev2payl_notify_h *)e->data->v;
					uint8_t *v = (uint8_t *)(h + 1);
					if (get_uint16(&h->notify_message_type) ==
					    IKEV2_AUTH_LIFETIME &&
					    v[0] == 0 && v[1] == 0 &&
					    v[2] == 0x1c && v[3] == 0x20)
						ok = 1;
				}
			}
			ck(pl.num == 1 && ok,
			   "auth_lifetime 7200 pushes one N(AUTH_LIFETIME, 7200)");
			ikev2_payloads_destroy(&pl);
		}
	}

	if (fails) {
		printf("notifytest: %d FAILURE(S)\n", fails);
		return 1;
	}
	printf("notifytest: all checks passed\n");
	return 0;
}
