/*
 * iked/radworkertest.c - prove the non-blocking RADIUS EAP integration.
 *
 * iked's main loop is single-threaded; calling the blocking
 * ikev2_radius_exchange() there would stall the whole daemon.  The
 * integration runs the (blocking) exchange on the existing worker pool
 * (crypto_job_submit -> worker_main) and resumes the IKE SA from the
 * done() callback, which iked's main loop invokes via crypto_workers_drain()
 * when the notify fd fires.  That drain/dispatch is the ONLY path in which
 * the RADIUS result may touch an IKE SA.
 *
 * This harness mirrors exactly that:  submit an Access-Request carrying an
 * EAP Identity response to a worker, let the pool complete the UDP round
 * trip to the live FreeRADIUS, drain on the "main thread", and print the
 * Access-Challenge + EAP-MSCHAPv2 response the worker obtained.  A pass
 * proves the worker-pool path delivers the RADIUS result back on the main
 * loop.  It does NOT close the blocking-event-loop gate by itself: for the
 * real daemon the gate still needs (1) the pool actually started for the
 * IKE SA (iked reads --with-crypto-workers / RACOON2_CRYPTO_WORKERS in
 * main.c; the tree default is 0 threads, so crypto_job_submit would run
 * fn+done INLINE and never write the notify fd, stalling the loop), (2)
 * done() must not touch a freed SA (serial revalidation / crypto_pending),
 * and (3) worker-thread plog (localtime) and the multi-second RADIUS
 * select sharing the DH pool.  This harness starts its own pool and manages
 * its own job, so a pass does not prove those three daemon-path gates.
 *
 * Operator harness (needs root + a running server + the secret file): NOT
 * in TESTS, like radiuslive.c.
 *
 * ORACLE: this exits non-zero unless the pool THIS BINARY started is real -
 * i.e. crypto_workers_enabled() is true immediately after crypto_workers_init().
 * The thread count is argv[3], default 2, so the shipped binary exercises a
 * real pool; pass argv[3]=0 to see the inline fallback FAIL (fn+done run on
 * the caller and never notify, which would stall iked's single-threaded
 * loop).  Note this harness does NOT read RACOON2_CRYPTO_WORKERS or
 * --with-crypto-workers - those are read only in iked/main.c - so a pass
 * here says nothing about how iked's own pool was configured.  A pass also
 * requires the reassembled EAP type to be 26 (MSCHAPv2) and a State
 * attribute (RFC 3579 session state).  A printed PASS is not the oracle;
 * the exit status is.
 *
 * Usage: radworkertest SECRET_FILE [IDENTITY] [NTHREADS]
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
#include "crypto_workers.h"

struct rjob {
	rc_vchar_t secret, eap;
	struct sockaddr_in server;
	struct ikev2_radius_opt opt;
	uint8_t id;
	int rv;
	struct ikev2_radius_response *resp;	/* worker result */
	char *ident;
};

/* runs on a WORKER thread */
static void
rjob_run(void *arg)
{
	struct rjob *j = arg;
	j->rv = ikev2_radius_exchange(
		(struct sockaddr *)&j->server, (socklen_t)sizeof(j->server),
		&j->eap, &j->opt, &j->id, &j->resp);
}

/* runs on the MAIN thread after drain - the exact future iked contract */
static void
rjob_done(void *arg)
{
	struct rjob *j = arg;
	int i;
	if (j->rv == IKEV2_RADIUS_OK && j->resp) {
		rc_vchar_t *eap;
		printf("worker result on main thread: code=%u\n", j->resp->code);
		eap = ikev2_radius_eap_message(j->resp);
		if (eap && eap->l >= 5)
			printf("  EAP-Message reassembled (%zu bytes): type=%u\n",
			       eap->l,
			       (unsigned)((uint8_t *)eap->v)[4]);
		if (eap)
			rc_vfree(eap);
		for (i = 0; i < (int)j->resp->nattrs; i++)
			if (j->resp->attrs[i].type == IKEV2_RADIUS_ATTR_STATE)
				printf("  State present (%zu octets)\n",
				       j->resp->attrs[i].value->l);
	}
}

int
main(int argc, char **argv)
{
	const char *secret_path = argc > 1 ? argv[1] : "/etc/racoon2/radius-secret";
	const char *ident = argc > 2 ? argv[2] : "radiuslocal";
	int nthreads = argc > 3 ? atoi(argv[3]) : 2;
	struct rjob *job;
	FILE *fp;
	uint8_t eap_ident[256];
	size_t idlen;
	int i, polled = 0, worker_done = 0;

	if (rbuf_init(8, 80, 8, 1000, 5))
		return 2;

	if (crypto_workers_init(nthreads) < 0) {
		fprintf(stderr, "workers init failed\n");
		return 2;
	}
	/* Decide whether the pool is real BEFORE we submit anything.  With
	 * nthreads<=0 (or no pthreads) crypto_job_submit runs fn+done inline
	 * and never writes the notify fd, so the poll below would time out
	 * and never reach this diagnostic - hence the early check.  Inline
	 * execution stalls iked's single-threaded loop and does NOT close the
	 * blocking gate; it must fail here, not after a wasted poll window. */
	if (!crypto_workers_enabled()) {
		printf("FAIL: crypto worker pool is not enabled "
		       "(nthreads=%d: inline fallback does not close the "
		       "blocking gate; iked needs --with-crypto-workers>0 / "
		       "RACOON2_CRYPTO_WORKERS>0)\n", nthreads);
		return 1;
	}

	job = calloc(1, sizeof(*job));
	if (!job)
		return 2;
	job->ident = strdup(ident);

	/* read the secret */
	fp = fopen(secret_path, "r");
	if (!fp) { perror("open secret"); return 2; }
	job->secret.v = malloc(256);
	job->secret.l = fread(job->secret.v, 1, 255, fp);
	fclose(fp);
	while (job->secret.l &&
	       (((uint8_t *)job->secret.v)[job->secret.l - 1] == '\n' ||
		((uint8_t *)job->secret.v)[job->secret.l - 1] == '\r' ||
		((uint8_t *)job->secret.v)[job->secret.l - 1] == ' '))
		job->secret.l--;

	/* EAP Identity Response */
	idlen = strlen(ident);
	if (idlen > 251) idlen = 251;
	eap_ident[0] = 2; eap_ident[1] = 1;
	eap_ident[2] = (uint8_t)((5 + idlen) >> 8);
	eap_ident[3] = (uint8_t)((5 + idlen) & 0xff);
	eap_ident[4] = 1;
	memcpy(eap_ident + 5, ident, idlen);
	job->eap.v = malloc(5 + idlen);
	if (!job->eap.v) return 2;
	memcpy(job->eap.v, eap_ident, 5 + idlen);
	job->eap.l = 5 + idlen;

	job->server.sin_family = AF_INET;
	job->server.sin_port = htons(1812);
	inet_pton(AF_INET, "127.0.0.1", &job->server.sin_addr);
	job->opt.secret = &job->secret;
	job->opt.user_name = ident;
	job->opt.nas_ip = "127.0.0.1";
	job->opt.retries = 2;
	job->opt.timeout_ms = 3000;
	job->id = 7;

	printf("submitting RADIUS exchange to a worker thread...\n");
	if (crypto_job_submit(rjob_run, rjob_done, job) != 0) {
		fprintf(stderr, "submit failed\n");
		return 2;
	}

	/* emulate the main loop: wait for the notify fd, then drain */
	for (i = 0; i < 50; i++) {
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
		return 1;
	}
	printf("main loop drained %d poll(s)\n", polled);

	/* The pool was verified enabled before submit (above); reaching this
	 * point through a real notify+drain is the non-blocking proof. */
	if (job->rv != IKEV2_RADIUS_OK || !job->resp) {
		printf("FAIL: exchange rc=%d on worker (wanted 0)\n", job->rv);
		return 1;
	}
	if (job->resp->code != IKEV2_RADIUS_CODE_ACCESS_CHALLENGE) {
		printf("FAIL: expected Access-Challenge (11), got code=%u\n",
		       job->resp->code);
		ikev2_radius_response_free(job->resp);
		return 1;
	}
	{
		rc_vchar_t *eap = ikev2_radius_eap_message(job->resp);
		int good = (eap && eap->l >= 5 &&
			    ((uint8_t *)eap->v)[4] == IKEV2_RADIUS_EAP_TYPE_MSCHAPV2);
		if (eap)
			rc_vfree(eap);
		if (!good) {
			printf("FAIL: reassembled EAP is not MSCHAPv2 (type 26)\n");
			ikev2_radius_response_free(job->resp);
			return 1;
		}
	}
	if (!ikev2_radius_find_attr(job->resp, IKEV2_RADIUS_ATTR_STATE)) {
		printf("FAIL: response has no State attribute (RFC 3579)\n");
		ikev2_radius_response_free(job->resp);
		return 1;
	}
	ikev2_radius_response_free(job->resp);
	printf("PASS: non-blocking RADIUS (code 11, EAP type 26, State) "
	       "completed on worker + drained on main\n");
	return 0;
}
