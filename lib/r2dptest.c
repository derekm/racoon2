/*
 * r2dptest: hermetic test of the r2dp KM backend (#includes if_r2dp.c)
 * against a fake forwarder on a private SOCK_SEQPACKET socket.
 *
 *  - reqid: SAs without an IKE-assigned reqid get a stable, non-zero,
 *    per-tunnel reqid (same pair -> same reqid, different pair or satype ->
 *    different); an explicit reqid passes through.
 *  - v2 dir: GETSPI/UPDATE carry R2DP_DIR_IN, ADD carries R2DP_DIR_OUT.
 *  - reconnect: after the forwarder drops the connection, the next request
 *    reconnects transparently on the SAME fd number when the epoch is
 *    unchanged; a changed epoch makes the daemon exit for a resync.
 */
#include "if_r2dp.c"

#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <sys/wait.h>
#include "rbuf.h"

static int fails;
#define CHECK(c, m) do { if (c) printf("ok   %s\n", m); \
	else { printf("FAIL %s\n", m); fails++; } } while (0)

static int lfd, conn = -1;
static uint64_t fwd_epoch = 0x1111;
static struct r2dp_sa last;
static unsigned last_type, nconns;
static sem_t got;

static void *
fwd_thread(void *arg)
{
	struct r2dp_msg *m = malloc(sizeof(*m));

	(void)arg;
	for (;;) {
		int c = accept(lfd, NULL, NULL);
		if (c < 0)
			break;
		__atomic_store_n(&conn, c, __ATOMIC_RELEASE);
		__atomic_add_fetch(&nconns, 1, __ATOMIC_RELEASE);
		for (;;) {
			int r = r2dp_recv(c, m);
			if (r == -ENOTCONN || r == -ECONNRESET || r == -EBADF)
				break;
			if (r < 0)
				continue;
			if (m->h.type == R2DP_HELLO) {
				struct r2dp_hello_ack a;
				memset(&a, 0, sizeof(a));
				a.epoch = fwd_epoch;
				a.max_msg = R2DP_MAX_MSG;
				a.enc_caps[0] = a.enc_caps[1] = ~0u;
				a.integ_caps[0] = ~0u;
				r2dp_send(c, R2DP_HELLO_ACK, m->h.seq, 0, 0,
				    &a, sizeof(a), NULL, 0);
				continue;
			}
			memcpy(&last, m->body, sizeof(last));
			last_type = m->h.type;
			r2dp_send(c, m->h.type, m->h.seq, 0, 0, &last,
			    sizeof(last), NULL, 0);
			sem_post(&got);
		}
		close(c);
	}
	free(m);
	return NULL;
}

static struct sockaddr_in A, B, C;
static char key[20] = "0123456789abcdefghij";

static void
fill(struct rcpfk_msg *rc, int so, struct sockaddr_in *s, struct sockaddr_in *d,
    uint32_t reqid, uint8_t satype)
{
	memset(rc, 0, sizeof(*rc));
	rc->so = so;
	rc->seq = 7;
	rc->sa_src = (struct sockaddr *)s;
	rc->sa_dst = (struct sockaddr *)d;
	rc->spi = htonl(0x1000);
	rc->reqid = reqid;
	rc->satype = satype;
	rc->samode = RCT_IPSM_TUNNEL;
	rc->enctype = satype == RCT_SATYPE_ESP ? RCT_ALG_AES_GCM : 0;
	rc->authtype = satype == RCT_SATYPE_AH ? RCT_ALG_HMAC_SHA2_256 : 0;
	rc->enckeylen = satype == RCT_SATYPE_ESP ? 20 : 0;
	rc->enckey = satype == RCT_SATYPE_ESP ? key : NULL;
	rc->authkeylen = satype == RCT_SATYPE_AH ? 16 : 0;
	rc->authkey = satype == RCT_SATYPE_AH ? key : NULL;
}

static int
wait_got(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_REALTIME, &ts);
	ts.tv_sec += 5;
	return sem_timedwait(&got, &ts) == 0;
}

/* send one SA request, return the reqid the forwarder saw (0 = none) */
static uint32_t
send_reqid(int (*fn)(struct rcpfk_msg *), int so, struct sockaddr_in *s,
    struct sockaddr_in *d, uint32_t reqid, uint8_t satype, uint8_t *dir)
{
	struct rcpfk_msg rc;

	fill(&rc, so, s, d, reqid, satype);
	if (fn(&rc) != 0 || !wait_got())
		return 0;
	if (dir)
		*dir = last.dir;
	return last.reqid;
}

static void
drop_conn(void)
{
	unsigned n = __atomic_load_n(&nconns, __ATOMIC_ACQUIRE);
	shutdown(__atomic_load_n(&conn, __ATOMIC_ACQUIRE), SHUT_RDWR);
	(void)n;
	usleep(100000);
}

int
main(void)
{
	char path[64];
	struct rcpfk_msg rc0;
	struct rcpfk_cb cbs;
	pthread_t th;
	uint32_t r1, r2, r3, r4;
	uint8_t dir = 0xff;
	int so;

	setvbuf(stdout, NULL, _IONBF, 0);
	if (rbuf_init(8, 80, 4, 160, 4))
		return 99;
	plog_setmode(RCT_LOGMODE_NORMAL, NULL, "r2dptest", 1, 0);
	signal(SIGPIPE, SIG_IGN);
	snprintf(path, sizeof(path), "/tmp/r2dptest.%d.sock", (int)getpid());
	unlink(path);
	setenv("R2DP_SOCK", path, 1);
	if ((lfd = r2dp_listen(path, 4)) < 0) {
		printf("SKIP: cannot listen on %s\n", path);
		return 77;
	}
	sem_init(&got, 0, 0);
	pthread_create(&th, NULL, fwd_thread, NULL);

	memset(&A, 0, sizeof(A)); A.sin_family = AF_INET;
	B = C = A;
	inet_pton(AF_INET, "192.0.2.1", &A.sin_addr);
	inet_pton(AF_INET, "192.0.2.2", &B.sin_addr);
	inet_pton(AF_INET, "192.0.2.3", &C.sin_addr);

	memset(&cbs, 0, sizeof(cbs));
	memset(&rc0, 0, sizeof(rc0));
	CHECK(rcpfk_init(&rc0, &cbs) == 0 && rc0.so >= 0, "init + HELLO");
	so = rc0.so;

	/* reqid */
	r1 = send_reqid(rcpfk_send_add, so, &A, &B, 0, RCT_SATYPE_ESP, &dir);
	r2 = send_reqid(rcpfk_send_add, so, &A, &B, 0, RCT_SATYPE_ESP, NULL);
	r3 = send_reqid(rcpfk_send_add, so, &A, &C, 0, RCT_SATYPE_ESP, NULL);
	r4 = send_reqid(rcpfk_send_add, so, &A, &B, 0, RCT_SATYPE_AH, NULL);
	CHECK(r1 != 0 && r1 == r2, "derived reqid non-zero and stable per tunnel");
	CHECK(r1 != r3, "different tunnel endpoints -> different reqid");
	CHECK(r1 != r4, "different satype -> different reqid");
	CHECK(r1 == tunnel_reqid((struct sockaddr *)&A, (struct sockaddr *)&B,
	    RCT_SATYPE_ESP), "reqid matches tunnel_reqid()");
	CHECK(send_reqid(rcpfk_send_add, so, &A, &B, 77, RCT_SATYPE_ESP, NULL) == 77,
	    "explicit IKE reqid passes through");

	/* v2 direction */
	CHECK(dir == R2DP_DIR_OUT, "SA_ADD carries dir=OUT");
	dir = 0xff;
	send_reqid(rcpfk_send_getspi, so, &B, &A, 0, RCT_SATYPE_ESP, &dir);
	CHECK(last_type == R2DP_GETSPI && dir == R2DP_DIR_IN, "GETSPI carries dir=IN");
	dir = 0xff;
	send_reqid(rcpfk_send_update, so, &B, &A, 0, RCT_SATYPE_ESP, &dir);
	CHECK(last_type == R2DP_SA_UPDATE && dir == R2DP_DIR_IN, "UPDATE carries dir=IN");
	dir = 0xff;
	send_reqid(rcpfk_send_delete, so, &B, &A, 0, RCT_SATYPE_ESP, &dir);
	CHECK(dir == 0, "SA_DEL leaves dir unset (lookup)");

	/* reconnect, same epoch: transparent, same fd number */
	drop_conn();
	{
		struct rcpfk_msg rc;
		fill(&rc, so, &A, &B, 0, RCT_SATYPE_ESP);
		CHECK(rcpfk_send_add(&rc) == 0 && wait_got(),
		    "request after forwarder drop succeeds (reconnected, same epoch)");
		CHECK(rc.so == so && __atomic_load_n(&nconns, __ATOMIC_ACQUIRE) == 2,
		    "reconnected on the same fd number");
	}

	/* reconnect, changed epoch: the daemon exits for resync */
	{
		pid_t p;
		int st = 0;

		fwd_epoch = 0x2222;
		drop_conn();
		p = fork();
		if (p == 0) {
			struct rcpfk_msg rc;
			fill(&rc, so, &A, &B, 0, RCT_SATYPE_ESP);
			(void)rcpfk_send_add(&rc);
			_exit(0);	/* not reached if the shim exits */
		}
		waitpid(p, &st, 0);
		CHECK(WIFEXITED(st) && WEXITSTATUS(st) == EXIT_FAILURE,
		    "forwarder restarted (epoch changed) -> exit for resync");
	}

	rcpfk_clean(&rc0);
	unlink(path);
	if (fails) {
		printf("r2dptest: %d failures\n", fails);
		return 1;
	}
	puts("r2dptest: OK");
	return 0;
}
