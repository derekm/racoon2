/* $Id$ */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#ifdef HAVE_PTHREAD
#include <pthread.h>
#endif

#include "racoon.h"
#include "debug.h"
#include "crypto_workers.h"

struct crypto_job {
	struct crypto_job *next;
	crypto_job_fn fn;
	crypto_job_fn done;
	void *arg;
};

static int nworkers;
static int notify[2] = { -1, -1 };

#ifdef HAVE_PTHREAD
static int stopping;
static pthread_mutex_t qlock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t qcv = PTHREAD_COND_INITIALIZER;
static pthread_t *tids;
static struct crypto_job *qhead;
static struct crypto_job **qtailp = &qhead;
static struct crypto_job *dhead;
static struct crypto_job **dtailp = &dhead;

static void
notify_write(void)
{
	char c = 1;
	if (write(notify[1], &c, 1) < 0)
		(void)0;	/* pipe wakeup is best-effort */
}

static void *
worker_main(void *arg)
{
	struct crypto_job *j;

	(void)arg;
	for (;;) {
		pthread_mutex_lock(&qlock);
		while (qhead == NULL && !stopping)
			pthread_cond_wait(&qcv, &qlock);
		if (stopping && qhead == NULL) {
			pthread_mutex_unlock(&qlock);
			return NULL;
		}
		j = qhead;
		qhead = j->next;
		if (qhead == NULL)
			qtailp = &qhead;
		pthread_mutex_unlock(&qlock);

		if (j->fn)
			j->fn(j->arg);

		pthread_mutex_lock(&qlock);
		j->next = NULL;
		*dtailp = j;
		dtailp = &j->next;
		pthread_mutex_unlock(&qlock);
		notify_write();
	}
}
#endif

int
crypto_workers_init(int nthreads)
{
#ifdef HAVE_PTHREAD
	stopping = 0;
#endif
	if (pipe(notify) < 0)
		return -1;
#ifdef F_SETFD
	(void)fcntl(notify[0], F_SETFD, FD_CLOEXEC);
	(void)fcntl(notify[1], F_SETFD, FD_CLOEXEC);
#endif
#ifdef O_NONBLOCK
	{
		int fl = fcntl(notify[0], F_GETFL);
		if (fl >= 0)
			(void)fcntl(notify[0], F_SETFL, fl | O_NONBLOCK);
	}
#endif
#ifndef HAVE_PTHREAD
	(void)nthreads;
	nworkers = 0;
	return 0;
#else
	if (nthreads <= 0) {
		nworkers = 0;
		return 0;
	}
	tids = calloc((size_t)nthreads, sizeof(*tids));
	if (tids == NULL) {
		close(notify[0]);
		close(notify[1]);
		notify[0] = notify[1] = -1;
		return -1;
	}
	nworkers = nthreads;
	{
		int i;
		for (i = 0; i < nthreads; i++) {
			if (pthread_create(&tids[i], NULL, worker_main, NULL) != 0) {
				nworkers = i;
				break;
			}
		}
	}
	plog(PLOG_INFO, PLOGLOC, NULL,
	    "crypto workers: %d thread%s\n", nworkers, nworkers == 1 ? "" : "s");
	return 0;
#endif
}

void
crypto_workers_fini(void)
{
#ifdef HAVE_PTHREAD
	int i;
	struct crypto_job *j, *n;

	if (nworkers > 0) {
		pthread_mutex_lock(&qlock);
		stopping = 1;
		pthread_cond_broadcast(&qcv);
		pthread_mutex_unlock(&qlock);
		for (i = 0; i < nworkers; i++)
			(void)pthread_join(tids[i], NULL);
		nworkers = 0;
	}
	free(tids);
	tids = NULL;
	/*
	 * Run the leftover done callbacks with rc=-1 instead of
	 * dropping them: the jobs' ctx (dup'd DH buffers) is owned by
	 * those callbacks, and every callback's failure branch only
	 * validates liveness and frees its ctx.  Runs on the IKE
	 * thread while the SA trees are still up (iked_exit calls us
	 * before evloop_fini).
	 */
	for (j = qhead; j; j = n) {
		n = j->next;
		if (j->done)
			j->done(j->arg);
		free(j);
	}
	qhead = NULL;
	qtailp = &qhead;
	for (j = dhead; j; j = n) {
		n = j->next;
		if (j->done)
			j->done(j->arg);
		free(j);
	}
	dhead = NULL;
	dtailp = &dhead;
	stopping = 0;
#endif
	if (notify[0] >= 0)
		close(notify[0]);
	if (notify[1] >= 0)
		close(notify[1]);
	notify[0] = notify[1] = -1;
}

int
crypto_workers_fd(void)
{
	return notify[0];
}

int
crypto_workers_enabled(void)
{
	return nworkers > 0;
}

int
crypto_workers_drain(void)
{
	char buf[32];

	if (notify[0] >= 0)
		while (read(notify[0], buf, sizeof(buf)) > 0)
			;
#ifndef HAVE_PTHREAD
	return 0;
#else
	{
		struct crypto_job *j, *n;

		pthread_mutex_lock(&qlock);
		j = dhead;
		dhead = NULL;
		dtailp = &dhead;
		pthread_mutex_unlock(&qlock);
		for (; j; j = n) {
			n = j->next;
			if (j->done)
				j->done(j->arg);
			free(j);
		}
	}
	return 0;
#endif
}

int
crypto_job_submit(crypto_job_fn fn, crypto_job_fn done, void *arg)
{
	struct crypto_job *j;

	if (fn == NULL)
		return -1;
#ifndef HAVE_PTHREAD
	fn(arg);
	if (done)
		done(arg);
	return 0;
#else
	if (nworkers <= 0) {
		fn(arg);
		if (done)
			done(arg);
		return 0;
	}
	j = calloc(1, sizeof(*j));
	if (j == NULL)
		return -1;
	j->fn = fn;
	j->done = done;
	j->arg = arg;
	pthread_mutex_lock(&qlock);
	*qtailp = j;
	qtailp = &j->next;
	pthread_cond_signal(&qcv);
	pthread_mutex_unlock(&qlock);
	return 0;
#endif
}
