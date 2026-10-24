/*
 * r2dp-mockfwd: protocol-faithful forwarder with no dataplane.  In-memory
 * SAD/SPD with kernel-like semantics (EEXIST/ENOENT, SPI allocation,
 * policy ids, dump streaming).  Used for contract tests and to develop
 * the racoon2 shim before any DPDK code exists.
 *
 *   r2dp-mockfwd [-s sockpath] [-v] [-K]
 *     -v  log every request   -K  echo keys in completions (tests only)
 */
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "r2dp/client.h"

#define MAXCLI 16
#define MAXSA  1024
#define MAXSP  1024

struct sa_ent { int used, larval; struct r2dp_sa sa;
                uint8_t enc[R2DP_MAX_KEY], auth[R2DP_MAX_KEY]; };
struct sp_ent { int used; struct r2dp_sp sp; };

static struct sa_ent sad[MAXSA];
static struct sp_ent spd[MAXSP];
static int verbose, echo_keys;
static uint32_t next_spi = 0x100, next_slid = 1;
static uint64_t epoch;
static volatile sig_atomic_t stop;

#define LOG(...) do { if (verbose) { fprintf(stderr, "mockfwd: " __VA_ARGS__); fputc('\n', stderr); } } while (0)

static void on_sig(int s) { (void)s; stop = 1; }

/* ------------------------------------------------------------------ SAD */
static struct sa_ent *sa_find(const struct r2dp_sa *k)
{
	for (int i = 0; i < MAXSA; i++)
		if (sad[i].used && sad[i].sa.spi == k->spi && sad[i].sa.proto == k->proto &&
		    r2dp_addr_eq(&sad[i].sa.dst, &k->dst))
			return &sad[i];
	return NULL;
}
static struct sa_ent *sa_alloc(void)
{
	for (int i = 0; i < MAXSA; i++) if (!sad[i].used) return &sad[i];
	return NULL;
}
static void sa_store(struct sa_ent *e, const struct r2dp_msg *m)
{
	const struct r2dp_sa *sa = r2dp_msg_sa(m);
	e->sa = *sa;
	memset(e->enc, 0, sizeof(e->enc)); memset(e->auth, 0, sizeof(e->auth));
	if (!(m->h.flags & R2DP_HF_NOKEYS)) {
		memcpy(e->enc, r2dp_msg_enckey(m), sa->enckeylen);
		memcpy(e->auth, r2dp_msg_authkey(m), sa->authkeylen);
	}
}

/* ------------------------------------------------------------------ SPD */
static int sel_eq(const struct r2dp_sp *a, const struct r2dp_sp *b)
{
	return a->dir == b->dir && a->ul_proto == b->ul_proto &&
	       a->pref_src == b->pref_src && a->pref_dst == b->pref_dst &&
	       r2dp_addr_eq(&a->sel_src, &b->sel_src) && a->sel_src.port == b->sel_src.port &&
	       r2dp_addr_eq(&a->sel_dst, &b->sel_dst) && a->sel_dst.port == b->sel_dst.port;
}
static struct sp_ent *sp_find(const struct r2dp_sp *k, int by_selector)
{
	for (int i = 0; i < MAXSP; i++) {
		if (!spd[i].used) continue;
		if (by_selector ? sel_eq(&spd[i].sp, k) : spd[i].sp.slid == k->slid)
			return &spd[i];
	}
	return NULL;
}

/* ------------------------------------------------------------- replying */
/* Completion for an SA request.  e != NULL => report stored state. */
static int reply_sa(int fd, const struct r2dp_msg *req, int status,
                    const struct sa_ent *e)
{
	const struct r2dp_sa *sa = e ? &e->sa : r2dp_msg_sa(req);
	uint8_t tail[2 * R2DP_MAX_KEY];
	size_t tl = 0;
	uint32_t fl = R2DP_HF_NOKEYS;

	if (e && echo_keys && !status) {
		memcpy(tail, e->enc, sa->enckeylen);
		memcpy(tail + sa->enckeylen, e->auth, sa->authkeylen);
		tl = (size_t)sa->enckeylen + sa->authkeylen;
		fl = 0;
	}
	return r2dp_send(fd, req->h.type, req->h.seq, status, fl,
	                 sa, sizeof(*sa), tail, tl);
}
static int reply_sp(int fd, const struct r2dp_msg *req, int status,
                    const struct r2dp_sp *sp, uint32_t flags)
{
	return r2dp_send(fd, req->h.type, req->h.seq, status, flags,
	                 sp, sizeof(*sp), NULL, 0);
}

static void log_sa(const char *op, const struct r2dp_sa *s)
{
	char d[INET6_ADDRSTRLEN] = "?";
	if (s->dst.family == R2DP_AF_INET4) inet_ntop(AF_INET, s->dst.addr, d, sizeof(d));
	else if (s->dst.family == R2DP_AF_INET6) inet_ntop(AF_INET6, s->dst.addr, d, sizeof(d));
	LOG("%s spi=0x%08x dst=%s proto=%u enc=%u integ=%u esn=%u natt=%u/%u enclen=%u authlen=%u reqid=%u",
	    op, ntohl(s->spi), d, s->proto, s->enc, s->integ, !!(s->saflags & R2DP_SAF_ESN),
	    s->natt_type, ntohs(s->natt_dport), s->enckeylen, s->authkeylen, s->reqid);
}

/* ------------------------------------------------------------- handlers */
static void do_hello(int fd, const struct r2dp_msg *m)
{
	struct r2dp_hello_ack a;
	const struct r2dp_hello *h = (const void *)m->body;
	memset(&a, 0, sizeof(a));
	a.epoch = epoch; a.max_msg = R2DP_MAX_MSG;
	a.features = R2DP_FEAT_ESN | R2DP_FEAT_NATT | R2DP_FEAT_IPV6 | R2DP_FEAT_EXPIRE;
	memset(a.enc_caps, 0xff, sizeof(a.enc_caps));
	memset(a.integ_caps, 0xff, sizeof(a.integ_caps));
	LOG("HELLO role=%u pid=%u", h->role, h->pid);
	r2dp_send(fd, R2DP_HELLO_ACK, m->h.seq, 0, 0, &a, sizeof(a), NULL, 0);
}

static void do_getspi(int fd, const struct r2dp_msg *m)
{
	const struct r2dp_sa *rq = r2dp_msg_sa(m);
	uint32_t lo = rq->spi_min ? rq->spi_min : 0x100;
	uint32_t hi = rq->spi_max ? rq->spi_max : 0x0fffffff;
	struct sa_ent *e;
	uint32_t cand;

	log_sa("GETSPI", rq);
	if (rq->dst.family == R2DP_AF_UNSET || lo > hi) { reply_sa(fd, m, EINVAL, NULL); return; }
	if (next_spi < lo || next_spi > hi) next_spi = lo;
	for (uint32_t tries = 0, span = hi - lo + 1; tries < span; tries++) {
		struct r2dp_sa k = *rq;
		cand = next_spi;
		next_spi = cand >= hi ? lo : cand + 1;
		k.spi = htonl(cand);
		if (sa_find(&k)) continue;
		if (!(e = sa_alloc())) { reply_sa(fd, m, ENOBUFS, NULL); return; }
		memset(e, 0, sizeof(*e));
		e->used = e->larval = 1;
		e->sa = *rq; e->sa.spi = htonl(cand);
		reply_sa(fd, m, 0, e);
		return;
	}
	reply_sa(fd, m, ENOSPC, NULL);
}

static void do_sa(int fd, const struct r2dp_msg *m)
{
	const struct r2dp_sa *rq = r2dp_msg_sa(m);
	struct sa_ent *e = sa_find(rq);

	switch (m->h.type) {
	case R2DP_SA_ADD:
		log_sa("SA_ADD", rq);
		if (e && !e->larval) { reply_sa(fd, m, EEXIST, NULL); return; }
		if (!e && !(e = sa_alloc())) { reply_sa(fd, m, ENOBUFS, NULL); return; }
		e->used = 1; e->larval = 0; sa_store(e, m);
		reply_sa(fd, m, 0, e); return;
	case R2DP_SA_UPDATE:
		log_sa("SA_UPDATE", rq);
		if (!e) { reply_sa(fd, m, ENOENT, NULL); return; }
		e->larval = 0; sa_store(e, m);
		reply_sa(fd, m, 0, e); return;
	case R2DP_SA_DEL:
		log_sa("SA_DEL", rq);
		if (!e) { reply_sa(fd, m, ENOENT, NULL); return; }
		reply_sa(fd, m, 0, e); e->used = 0; return;
	case R2DP_SA_GET:
		log_sa("SA_GET", rq);
		if (!e || e->larval) { reply_sa(fd, m, ENOENT, NULL); return; }
		reply_sa(fd, m, 0, e); return;
	}
}

static void do_sp(int fd, const struct r2dp_msg *m)
{
	const struct r2dp_sp *rq = r2dp_msg_sp(m);
	struct sp_ent *e;
	struct r2dp_sp out;

	switch (m->h.type) {
	case R2DP_SP_ADD:
		LOG("SP_ADD dir=%u proto=%u pref=%u/%u action=%u mode=%u protos=0x%x reqid=%u upd=%u",
		    rq->dir, rq->ul_proto, rq->pref_src, rq->pref_dst, rq->action,
		    rq->mode, rq->protos, rq->reqid, !!(rq->flags & R2DP_SPF_UPDATE));
		e = sp_find(rq, 1);
		if (e && !(rq->flags & R2DP_SPF_UPDATE)) { reply_sp(fd, m, EEXIST, rq, 0); return; }
		if (!e) {
			for (int i = 0; i < MAXSP && !e; i++) if (!spd[i].used) e = &spd[i];
			if (!e) { reply_sp(fd, m, ENOBUFS, rq, 0); return; }
			e->used = 1;
			out = *rq; out.slid = rq->slid ? rq->slid : next_slid++;
		} else {
			out = *rq; out.slid = e->sp.slid;
		}
		out.flags &= ~R2DP_SPF_UPDATE;
		e->sp = out;
		reply_sp(fd, m, 0, &out, 0); return;
	case R2DP_SP_DEL:
		LOG("SP_DEL slid=%u", rq->slid);
		e = rq->slid ? sp_find(rq, 0) : sp_find(rq, 1);
		if (!e) { reply_sp(fd, m, ENOENT, rq, 0); return; }
		out = e->sp; e->used = 0;
		reply_sp(fd, m, 0, &out, 0); return;
	case R2DP_SP_GET:
		LOG("SP_GET slid=%u", rq->slid);
		e = sp_find(rq, 0);
		if (!e) { reply_sp(fd, m, ENOENT, rq, 0); return; }
		reply_sp(fd, m, 0, &e->sp, 0); return;
	case R2DP_SP_DUMP: {
		int last = -1;
		LOG("SP_DUMP");
		for (int i = 0; i < MAXSP; i++) if (spd[i].used) last = i;
		if (last < 0) { reply_sp(fd, m, ENOENT, rq, 0); return; }
		for (int i = 0; i <= last; i++)
			if (spd[i].used) {
				int more = 0;
				for (int j = i + 1; j <= last; j++) if (spd[j].used) { more = 1; break; }
				reply_sp(fd, m, 0, &spd[i].sp, more ? R2DP_HF_MORE : 0);
			}
		return; }
	}
}

static void dispatch(int fd, const struct r2dp_msg *m)
{
	switch (m->h.type) {
	case R2DP_HELLO:  do_hello(fd, m); break;
	case R2DP_GETSPI: do_getspi(fd, m); break;
	case R2DP_SA_ADD: case R2DP_SA_UPDATE: case R2DP_SA_DEL: case R2DP_SA_GET:
		do_sa(fd, m); break;
	case R2DP_SP_ADD: case R2DP_SP_DEL: case R2DP_SP_GET: case R2DP_SP_DUMP:
		do_sp(fd, m); break;
	default: /* HELLO_ACK/EXPIRE/ACQUIRE are forwarder->client only:
	          * refuse, echoing the (already validated) request body */
		r2dp_send(fd, m->h.type, m->h.seq, EPROTO, m->h.flags | R2DP_HF_NOKEYS,
		          m->body, m->h.len - sizeof(m->h), NULL, 0);
	}
}

int main(int argc, char **argv)
{
	const char *path = NULL;
	struct pollfd pf[MAXCLI + 1];
	int c, lfd, ncli = 0, cli[MAXCLI];

	while ((c = getopt(argc, argv, "s:vK")) != -1) {
		switch (c) {
		case 's': path = optarg; break;
		case 'v': verbose = 1; break;
		case 'K': echo_keys = 1; break;
		default: fprintf(stderr, "usage: %s [-s sock] [-v] [-K]\n", argv[0]); return 2;
		}
	}
	epoch = ((uint64_t)time(NULL) << 20) ^ (uint64_t)getpid();
	signal(SIGINT, on_sig); signal(SIGTERM, on_sig); signal(SIGPIPE, SIG_IGN);

	if ((lfd = r2dp_listen(path, 8)) < 0) {
		fprintf(stderr, "mockfwd: listen: %s\n", strerror(-lfd)); return 1;
	}
	LOG("listening epoch=%llu", (unsigned long long)epoch);

	while (!stop) {
		int n = 0, r;
		pf[n].fd = lfd; pf[n++].events = POLLIN;
		for (int i = 0; i < ncli; i++) { pf[n].fd = cli[i]; pf[n++].events = POLLIN; }
		if (poll(pf, n, -1) < 0) { if (errno == EINTR) continue; break; }
		if (pf[0].revents & POLLIN) {
			int fd = r2dp_accept(lfd);
			if (fd >= 0 && ncli < MAXCLI) cli[ncli++] = fd;
			else if (fd >= 0) close(fd);
		}
		for (int i = 0; i < ncli; i++) {
			struct r2dp_msg m;
			if (!(pf[i + 1].revents & (POLLIN | POLLHUP | POLLERR))) continue;
			r = r2dp_recv(cli[i], &m);
			if (r == 0) { dispatch(cli[i], &m); continue; }
			if (r == -ENOSYS) {
				r2dp_send(cli[i], m.h.type, m.h.seq, ENOSYS, R2DP_HF_NOKEYS, NULL, 0, NULL, 0);
				continue;
			}
			LOG("drop client fd=%d: %s", cli[i], strerror(-r));
			close(cli[i]); cli[i--] = cli[--ncli];
			break;   /* pollfd array is stale after removal */
		}
	}
	return 0;
}
