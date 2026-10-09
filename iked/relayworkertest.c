/*
 * iked/relayworkertest.c - prove the responder EAP relay driven through the
 * worker pool, live against FreeRADIUS.
 *
 * This closes the loop that radworkertest (worker -> exchange) and
 * relaytest (decoded response -> relay state machine) prove separately:
 *
 *   1. ikev2_eap_relay_start() emits the EAP Identity Request the IKE_AUTH
 *      responder would send the client (RFC 3748 s5.1).
 *   2. the client's EAP Identity Response is submitted to the worker pool
 *      (crypto_job_submit), which runs the blocking ikev2_radius_exchange()
 *      off the main thread - exactly the non-blocking contract the IKE_AUTH
 *      wiring uses (and which stalls had ikev2 run it inline).
 *   3. the main thread drains (crypto_workers_drain) and calls
 *      ikev2_eap_relay_consume() with the decoded Access-Challenge, the same
 *      way the responder will; consume() must return CONTINUE with the next
 *      EAP Request for the client (the MSCHAPv2 challenge, type 26) and
 *      remember the State attr (RFC 3579).
 *
 * ORACLE: exits non-zero unless the pool THIS BINARY started is enabled
 * (crypto_workers_enabled() right after init; nthreads is argv[3], default
 * 2 - this harness does NOT read RACOON2_CRYPTO_WORKERS / --with-crypto-
 * workers, which only iked/main.c reads), the exchange returns OK, consume()
 * returns CONTINUE, the relay's next EAP Request for the client is a
 * Request(1) of type 26 (MSCHAPv2), and State was captured.
 *
 * Operator harness (root + live server + secret file): NOT in TESTS, like
 * radworkertest / radiuslive.
 *
 * Usage: relayworkertest SECRET_FILE [IDENTITY] [NTHREADS]
 */
#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "racoon.h"
#include "gcmalloc.h"
#include "vmbuf.h"
#include "ikev2_radius.h"
#include "ikev2_eap.h"
#include "ikev2_eap_relay.h"
#include "crypto_workers.h"

struct rrelayjob {
	rc_vchar_t secret, eap;		/* secret; the EAP to send to RADIUS */
	struct sockaddr_in server;
	struct ikev2_radius_opt opt;
	uint8_t id;
	int rv;
	struct ikev2_radius_response *resp;	/* worker result */
};

/* runs on a WORKER thread */
static void
rrelay_run(void *arg)
{
	struct rrelayjob *j = arg;
	j->rv = ikev2_radius_exchange(
		(struct sockaddr *)&j->server, (socklen_t)sizeof(j->server),
		&j->eap, &j->opt, &j->id, &j->resp);
}

/* runs on the MAIN thread after drain - the future iked responder contract */
static void
rrelay_done(void *arg)
{
	struct rrelayjob *j = arg;
	if (j->rv == IKEV2_RADIUS_OK && j->resp) {
		rc_vchar_t *eap = ikev2_radius_eap_message(j->resp);
		printf("worker -> main: code=%u", j->resp->code);
		if (eap && eap->l >= 5)
			printf(", EAP type=%u", (unsigned)((uint8_t *)eap->v)[4]);
		if (eap)
			rc_vfree(eap);
		printf("\n");
	}
}

int
main(int argc, char **argv)
{
	const char *secret_path = argc > 1 ? argv[1] : "/etc/racoon2/radius-secret";
	const char *ident = argc > 2 ? argv[2] : "radiuslocal";
	int nthreads = argc > 3 ? atoi(argv[3]) : 2;
	struct rrelayjob *j;
	struct ikev2_eap_relay relay;
	rc_vchar_t *opener = NULL, *next = NULL, *msk = NULL;
	enum ikev2_eap_relay_result res;
	FILE *fp;
	uint8_t eap_ident[256];
	size_t idlen;
	int i, polled = 0, worker_done = 0;
	int failed = 1;

	if (rbuf_init(8, 80, 8, 1000, 5))
		return 2;

	/* the relay must start with a real pool BEFORE submit (inline would
	 * run exchange on the caller and stall iked's loop - must not pass). */
	if (crypto_workers_init(nthreads) < 0) {
		fprintf(stderr, "workers init failed\n");
		return 2;
	}
	if (!crypto_workers_enabled()) {
		printf("FAIL: crypto worker pool is not enabled (nthreads=%d: "
		       "re-run with a non-zero NTHREADS argument)\n", nthreads);
		return 1;
	}

	j = calloc(1, sizeof(*j));
	if (!j)
		return 2;

	/* read the secret */
	fp = fopen(secret_path, "r");
	if (!fp) { perror("open secret"); return 2; }
	j->secret.v = malloc(256);
	j->secret.l = fread(j->secret.v, 1, 255, fp);
	fclose(fp);
	while (j->secret.l &&
	       (((uint8_t *)j->secret.v)[j->secret.l - 1] == '\n' ||
		((uint8_t *)j->secret.v)[j->secret.l - 1] == '\r' ||
		((uint8_t *)j->secret.v)[j->secret.l - 1] == ' '))
		j->secret.l--;

	/* 1. relay starts the exchange: the Identity Request for the client */
	memset(&relay, 0, sizeof(relay));
	opener = ikev2_eap_relay_start(&relay, 7);
	if (!opener) {
		printf("FAIL: relay_start\n");
		goto out;
	}
	printf("relay start: EAP Identity Request (%zu bytes)\n", opener->l);

	/* 2. the client's EAP Identity Response is what goes to RADIUS.  An
	 * EAP Response/Identity (code 2, type 1, id 8) mentioning the user. */
	idlen = strlen(ident);
	if (idlen > 245) idlen = 245;
	eap_ident[0] = 2; eap_ident[1] = 8;			/* Response, id */
	eap_ident[2] = (uint8_t)((5 + idlen) >> 8);
	eap_ident[3] = (uint8_t)((5 + idlen) & 0xff);
	eap_ident[4] = 1;					/* Type=Identity */
	memcpy(eap_ident + 5, ident, idlen);
	j->eap.v = malloc(5 + idlen);
	if (!j->eap.v) goto out;
	memcpy(j->eap.v, eap_ident, 5 + idlen);
	j->eap.l = 5 + idlen;

	j->server.sin_family = AF_INET;
	j->server.sin_port = htons(1812);
	inet_pton(AF_INET, "127.0.0.1", &j->server.sin_addr);
	j->opt.secret = &j->secret;
	j->opt.user_name = ident;
	j->opt.nas_ip = "127.0.0.1";
	j->opt.retries = 2;
	j->opt.timeout_ms = 3000;
	j->id = 7;

	printf("submitting client EAP Identity to a worker...\n");
	if (crypto_job_submit(rrelay_run, rrelay_done, j) != 0) {
		printf("FAIL: submit\n");
		goto out;
	}

	/* emulate iked's main loop: wait for the notify fd then drain */
	for (i = 0; i < 60; i++) {
		fd_set rfd; struct timeval tv;
		FD_ZERO(&rfd);
		FD_SET(crypto_workers_fd(), &rfd);
		tv.tv_sec = 0; tv.tv_usec = 200000;
		if (select(crypto_workers_fd() + 1, &rfd, NULL, NULL, &tv) > 0 &&
		    FD_ISSET(crypto_workers_fd(), &rfd)) {
			crypto_workers_drain();
			polled++;
			worker_done = 1;
			break;
		}
		if (i % 10 == 9)
			printf("  (still waiting for worker...)\n");
	}
	if (!worker_done) {
		printf("FAIL: worker did not complete within the poll window\n");
		goto out;
	}
	printf("main loop drained %d poll(s)\n", polled);

	if (j->rv != IKEV2_RADIUS_OK || !j->resp) {
		printf("FAIL: exchange rc=%d on worker\n", j->rv);
		goto out;
	}
	if (j->resp->code != IKEV2_RADIUS_CODE_ACCESS_CHALLENGE) {
		printf("FAIL: expected Access-Challenge (11), got code=%u\n",
		       j->resp->code);
		goto out;
	}

	/* 3. the decoded response drives the relay state machine: it must
	 * produce the next EAP Request for the client (MSCHAPv2, type 26)
	 * and capture State. */
	next = NULL; msk = NULL;
	res = ikev2_eap_relay_consume(&relay, j->resp, &j->secret, &next, &msk);
	if (res != IKEV2_EAP_RELAY_CONTINUE || !next || msk) {
		printf("FAIL: relay consume returned %d (want CONTINUE) "
		       "next=%p msk=%p\n", res, (void *)next, (void *)msk);
		goto out;
	}
	{
		uint8_t *v = (uint8_t *)next->v;
		int code = v[0], type = v[4];
		if (next->l <= 4 || code != 1 /* Request */ ||
		    next->l < 5 || type != IKEV2_RADIUS_EAP_TYPE_MSCHAPV2) {
			printf("FAIL: relay next EAP is not MSCHAPv2 Request "
			       "(code=%d type=%d len=%zu)\n",
			       code >= 0 ? code : -1, type, next->l);
			goto out;
		}
		if (!relay.state || relay.state->l == 0) {
			printf("FAIL: relay did not capture State\n");
			goto out;
		}
		printf("relay -> client: EAP Request type 26 (MSCHAPv2) "
		       "(%zu bytes), State %zu octets captured\n",
		       next->l, relay.state->l);
	}
	failed = 0;
	printf("PASS: worker exchange + relay consume -> MSCHAPv2 challenge, "
	       "State captured (actual responder wiring contract)\n");

      out:
	if (next) rc_vfree(next);
	if (msk) rc_vfree(msk);
	if (opener) rc_vfree(opener);
	if (j->resp) ikev2_radius_response_free(j->resp);
	free(j->eap.v);
	if (j->secret.v) free(j->secret.v);
	free(j);
	ikev2_eap_relay_free(&relay);
	return failed ? 1 : 0;
}
