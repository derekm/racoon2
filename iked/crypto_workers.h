/* $Id$ */
#ifndef _IKED_CRYPTO_WORKERS_H
#define _IKED_CRYPTO_WORKERS_H

struct crypto_job;

typedef void (*crypto_job_fn)(void *arg);

int crypto_workers_init(int nthreads);
void crypto_workers_fini(void);
int crypto_workers_fd(void);
int crypto_workers_enabled(void);
int crypto_workers_drain(void);

/*
 * Run fn(arg) on a worker. done(arg) is invoked on the main thread
 * after drain. If workers are disabled, fn+done run inline.
 */
int crypto_job_submit(crypto_job_fn fn, crypto_job_fn done, void *arg);

#endif
