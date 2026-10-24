/*
 * Mock-socket unit test for the NETLINK_XFRM backend's socket model
 * (lib/if_xfrm.c): separate request/notification sockets, reply matching
 * by seq/pid, RFC 0002-style error classification (EEXIST/ENOENT/ESRCH
 * idempotence, bounded EBUSY retry), ENOBUFS drain + SAD/SPD resync,
 * MAPPING/MIGRATE delivery and per-message containers.
 *
 * The kernel is replaced by two AF_UNIX SOCK_DGRAM socketpairs; this file
 * #includes if_xfrm.c with XFRM_UNITTEST so the test sees its statics.
 * No root, no netlink.  Socket-model ideas follow rdratlos/
 * racoon-ipsec-tools docs/rfcs/0002 (KernelPaws); no code was copied.
 *
 * Copyright (C) 2026 racoon2 contributors.  BSD-3-Clause (see COPYRIGHT).
 */
#define XFRM_UNITTEST 1
#include "if_xfrm.c"


#include <assert.h>
#include <arpa/inet.h>
#include <pthread.h>

#define PORTID 4242u

static int k_req = -1, k_ntf = -1;	/* "kernel" ends */
static int fails;
static struct rcpfk_msg rcm;

static int n_add, n_upd, n_del, n_spdadd, n_spdupd, n_spddel, n_spddump;
static int n_sadump, n_resync, n_mapping, n_migrate, n_acquire, n_getspi;
static int acquire_saw_sa2;
static struct rcpfk_msg last;

#define CHECK(c, ...) do { if (!(c)) { fails++; printf("FAIL %s:%d: ", \
	__func__, __LINE__); printf(__VA_ARGS__); printf("\n"); } } while (0)

static int cb_add(struct rcpfk_msg *r) { n_add++; last = *r; return 0; }
static int cb_upd(struct rcpfk_msg *r) { n_upd++; last = *r; return 0; }
static int cb_del(struct rcpfk_msg *r) { n_del++; last = *r; return 0; }
static int cb_getspi(struct rcpfk_msg *r) { n_getspi++; last = *r; return 0; }
static int cb_spdadd(struct rcpfk_msg *r) { n_spdadd++; last = *r; return 0; }
static int cb_spdupd(struct rcpfk_msg *r) { n_spdupd++; last = *r; return 0; }
static int cb_spddel(struct rcpfk_msg *r) { n_spddel++; last = *r; return 0; }
static int dump_flag_ok = 1;
static int cb_spddump(struct rcpfk_msg *r)
{
	n_spddump++;
	if (!(r->flags & PFK_FLAG_RESYNC))
		dump_flag_ok = 0;
	return 0;
}
static int cb_sadump(struct rcpfk_msg *r)
{
	n_sadump++;
	if (!(r->flags & PFK_FLAG_RESYNC))
		dump_flag_ok = 0;
	return 0;
}
static int cb_resync(struct rcpfk_msg *r) { n_resync++; (void)r; return 0; }
/* the container is per-message scratch: keep a copy of what it points at */
static struct sockaddr_storage last_sa2;
static void
keep(struct rcpfk_msg *r)
{
	last = *r;
	if (r->sa2_src) {
		memcpy(&last_sa2, r->sa2_src, sizeof(struct sockaddr_in));
		last.sa2_src = (void *)&last_sa2;
	}
	last.sa_src = last.sa_dst = last.sp_src = last.sp_dst = NULL;
}
static int cb_mapping(struct rcpfk_msg *r) { n_mapping++; keep(r); return 0; }
#ifdef SADB_X_MIGRATE
static int cb_migrate(struct rcpfk_msg *r) { n_migrate++; keep(r); return 0; }
#endif
static int
cb_acquire(struct rcpfk_msg *r)
{
	n_acquire++;
	acquire_saw_sa2 = r->sa2_src != NULL;
	return 0;
}

static struct rcpfk_cb tcb;

static void
reset_counts(void)
{
	n_add = n_upd = n_del = n_spdadd = n_spdupd = n_spddel = n_spddump = 0;
	n_sadump = n_resync = n_mapping = n_migrate = n_acquire = n_getspi = 0;
	memset(&last, 0, sizeof(last));
}

static void
setup(void)
{
	int a[2], b[2];

	if (k_req >= 0) {
		close(k_req);
		close(k_ntf);
	}
	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, a) || socketpair(AF_UNIX,
	    SOCK_DGRAM, 0, b)) {
		perror("socketpair");
		exit(99);
	}
	/* library reads ntf non-blocking */
	fcntl(b[0], F_SETFL, fcntl(b[0], F_GETFL) | O_NONBLOCK);
	memset(&rcm, 0, sizeof(rcm));
	memset(&tcb, 0, sizeof(tcb));
	tcb.cb_add = cb_add;
	tcb.cb_update = cb_upd;
	tcb.cb_delete = cb_del;
	tcb.cb_getspi = cb_getspi;
	tcb.cb_spdadd = cb_spdadd;
	tcb.cb_spdupdate = cb_spdupd;
	tcb.cb_spddelete = cb_spddel;
	tcb.cb_spddump = cb_spddump;
	tcb.cb_sadump = cb_sadump;
	tcb.cb_resync = cb_resync;
	tcb.cb_mapping = cb_mapping;
	tcb.cb_acquire = cb_acquire;
#ifdef SADB_X_MIGRATE
	tcb.cb_migrate = cb_migrate;
#endif
	if (xfrm_test_open(&rcm, &tcb, a[0], b[0], PORTID)) {
		perror("xfrm_test_open");
		exit(99);
	}
	k_req = a[1];
	k_ntf = b[1];
	xfrm_stat_enobufs = xfrm_stat_resync = xfrm_stat_idempotent = 0;
	xfrm_stat_ebusy_retry = xfrm_stat_stale_reply = 0;
	xfrm_stat_late_error = xfrm_stat_trunc = 0;
	reset_counts();
}

/* --- message builders ("kernel" side) --- */

static size_t
mk_err(char *buf, uint32_t seq, uint32_t pidv, int err, uint16_t origtype)
{
	struct nlmsghdr *n = (void *)buf;
	struct nlmsgerr *e;

	memset(buf, 0, NLMSG_SPACE(sizeof(*e)));
	n->nlmsg_len = NLMSG_LENGTH(sizeof(*e));
	n->nlmsg_type = NLMSG_ERROR;
	n->nlmsg_seq = seq;
	n->nlmsg_pid = pidv;
	e = NLMSG_DATA(n);
	e->error = -err;
	e->msg.nlmsg_seq = seq;
	e->msg.nlmsg_pid = pidv;
	e->msg.nlmsg_type = origtype;
	return n->nlmsg_len;
}

static void
v4(xfrm_address_t *a, const char *s)
{
	memset(a, 0, sizeof(*a));
	inet_pton(AF_INET, s, &a->a4);
}

static size_t
mk_policy(char *buf, uint16_t type, uint32_t seq, uint32_t pidv,
    const char *src, const char *dst, uint16_t flags)
{
	struct nlmsghdr *n = (void *)buf;
	struct xfrm_userpolicy_info *xp;

	memset(buf, 0, NLMSG_SPACE(sizeof(*xp)));
	n->nlmsg_len = NLMSG_LENGTH(sizeof(*xp));
	n->nlmsg_type = type;
	n->nlmsg_flags = flags;
	n->nlmsg_seq = seq;
	n->nlmsg_pid = pidv;
	xp = NLMSG_DATA(n);
	xp->sel.family = AF_INET;
	v4(&xp->sel.saddr, src);
	v4(&xp->sel.daddr, dst);
	xp->sel.prefixlen_s = 32;
	xp->sel.prefixlen_d = 24;
	xp->dir = XFRM_POLICY_OUT;
	xp->index = 0x1234;
	return n->nlmsg_len;
}

static size_t
mk_sa(char *buf, uint16_t type, uint32_t seq, uint32_t pidv, uint32_t spi,
    uint16_t flags)
{
	struct nlmsghdr *n = (void *)buf;
	struct xfrm_usersa_info *sa;

	memset(buf, 0, NLMSG_SPACE(sizeof(*sa)));
	n->nlmsg_len = NLMSG_LENGTH(sizeof(*sa));
	n->nlmsg_type = type;
	n->nlmsg_flags = flags;
	n->nlmsg_seq = seq;
	n->nlmsg_pid = pidv;
	sa = NLMSG_DATA(n);
	sa->family = AF_INET;
	v4(&sa->saddr, "192.0.2.1");
	v4(&sa->id.daddr, "192.0.2.2");
	sa->id.spi = htonl(spi);
	sa->id.proto = IPPROTO_ESP;
	sa->lft.soft_add_expires_seconds = 100;
	sa->curlft.add_time = 1000;
	sa->curlft.packets = 5;
	return n->nlmsg_len;
}

static size_t
mk_done(char *buf, uint32_t seq, uint32_t pidv)
{
	struct nlmsghdr *n = (void *)buf;

	memset(buf, 0, NLMSG_SPACE(sizeof(int)));
	n->nlmsg_len = NLMSG_LENGTH(sizeof(int));
	n->nlmsg_type = NLMSG_DONE;
	n->nlmsg_flags = NLM_F_MULTI;
	n->nlmsg_seq = seq;
	n->nlmsg_pid = pidv;
	return n->nlmsg_len;
}

static void
kput(int fd, const void *buf, size_t len)
{
	if (send(fd, buf, len, 0) != (ssize_t)len) {
		perror("send");
		exit(99);
	}
}

/* read one request the library sent; returns its header (static buf) */
static struct nlmsghdr *
kget(void)
{
	static char buf[XFRM_BUFLEN];
	ssize_t n = recv(k_req, buf, sizeof(buf), MSG_DONTWAIT);

	if (n < (ssize_t)sizeof(struct nlmsghdr))
		return NULL;
	return (void *)buf;
}

static void
fill_sa_rc(struct rcpfk_msg *rc, struct sockaddr_in *s, struct sockaddr_in *d,
    uint32_t seq, uint32_t spi)
{
	memset(rc, 0, sizeof(*rc));
	memset(s, 0, sizeof(*s));
	memset(d, 0, sizeof(*d));
	s->sin_family = d->sin_family = AF_INET;
	inet_pton(AF_INET, "192.0.2.1", &s->sin_addr);
	inet_pton(AF_INET, "192.0.2.2", &d->sin_addr);
	rc->sa_src = (void *)s;
	rc->sa_dst = (void *)d;
	rc->seq = seq;
	rc->spi = htonl(spi);
	rc->satype = RCT_SATYPE_ESP;
	rc->samode = RCT_IPSM_TUNNEL;
	rc->so = rcm.so;
}

/* --- tests --- */

static void
test_request_goes_to_req_socket(void)
{
	struct rcpfk_msg rc;
	struct sockaddr_in s, d;
	struct nlmsghdr *n;
	char tmp[64];

	setup();
	fill_sa_rc(&rc, &s, &d, 0x4000001, 0x1001);
	CHECK(rcpfk_send_delete(&rc) == 0, "send_delete: %s", rc.estr);
	n = kget();
	CHECK(n && n->nlmsg_type == XFRM_MSG_DELSA, "DELSA on request socket");
	CHECK(n && n->nlmsg_seq == 0x4000001 && n->nlmsg_pid == PORTID,
	    "seq/pid stamped (seq %u pid %u)", n ? n->nlmsg_seq : 0,
	    n ? n->nlmsg_pid : 0);
	CHECK(recv(k_ntf, tmp, sizeof(tmp), MSG_DONTWAIT) < 0,
	    "nothing sent on the notification socket");
	CHECK(rcm.so >= 0 && rcm.so != xfrm_req_fd && rcm.so != xfrm_ntf_fd,
	    "rc->so is the epoll fd");
}

static void
idem(uint16_t optype, int err, int expect_ok, int *counter, const char *what)
{
	struct rcpfk_msg rc;
	struct sockaddr_in s, d;
	char buf[256];
	int before = *counter, r;

	fill_sa_rc(&rc, &s, &d, 0x4000100 + optype, 0x2002);
	rc.pltype = RCT_ACT_AUTO_IPSEC;
	switch (optype) {
	case XFRM_MSG_NEWSA:
		rc.enctype = RCT_ALG_AES_GCM; rc.enckeylen = 20;
		rc.enckey = (caddr_t)"0123456789abcdefghij";
		r = rcpfk_send_add(&rc); break;
	case XFRM_MSG_DELSA:
		r = rcpfk_send_delete(&rc); break;
	case XFRM_MSG_NEWPOLICY:
		rc.pltype = RCT_ACT_DISCARD;
		r = rcpfk_send_spdadd(&rc); break;
	case XFRM_MSG_DELPOLICY:
		r = rcpfk_send_spddelete(&rc); break;
	default:
		r = -1;
	}
	CHECK(r == 0, "%s: send failed: %s", what, rc.estr);
	(void)kget();
	kput(k_req, buf, mk_err(buf, rc.seq, PORTID, err, optype));
	memset(&rc, 0, sizeof(rc));
	rc.so = rcm.so;
	r = rcpfk_handler(&rc);
	if (expect_ok) {
		CHECK(r == 0, "%s: %s must be success, got %d (%s)", what,
		    strerror(err), r, rc.estr);
		CHECK(*counter == before + 1, "%s: callback fired once (%d)",
		    what, *counter - before);
	} else {
		CHECK(r == -1 && rc.eno == err, "%s: %s must be an error (r=%d "
		    "eno=%d)", what, strerror(err), r, rc.eno);
		CHECK(*counter == before, "%s: no success callback", what);
	}
	CHECK(xfrm_nops == 0, "%s: pending op cleared", what);
}

static void
test_idempotence(void)
{
	setup();
	idem(XFRM_MSG_NEWSA, EEXIST, 1, &n_add, "NEWSA/EEXIST");
	idem(XFRM_MSG_DELSA, ENOENT, 1, &n_del, "DELSA/ENOENT");
	idem(XFRM_MSG_DELSA, ESRCH, 1, &n_del, "DELSA/ESRCH");
	idem(XFRM_MSG_NEWPOLICY, EEXIST, 1, &n_spdadd, "NEWPOLICY/EEXIST");
	idem(XFRM_MSG_DELPOLICY, ENOENT, 1, &n_spddel, "DELPOLICY/ENOENT");
	CHECK(xfrm_stat_idempotent == 5, "5 idempotent ACKs counted (%lu)",
	    xfrm_stat_idempotent);
	/* the classification is per message type, not blanket */
	idem(XFRM_MSG_NEWSA, ENOENT, 0, &n_add, "NEWSA/ENOENT");
	idem(XFRM_MSG_DELSA, EEXIST, 0, &n_del, "DELSA/EEXIST");
	idem(XFRM_MSG_DELSA, EINVAL, 0, &n_del, "DELSA/EINVAL");
	idem(XFRM_MSG_NEWPOLICY, EPERM, 0, &n_spdadd, "NEWPOLICY/EPERM");
}

static void
test_ebusy_retry(void)
{
	struct rcpfk_msg rc;
	struct sockaddr_in s, d;
	char buf[256], first[XFRM_BUFLEN];
	struct nlmsghdr *n;
	size_t flen;
	int i, r;

	setup();
	fill_sa_rc(&rc, &s, &d, 0x4000200, 0x3003);
	CHECK(rcpfk_send_delete(&rc) == 0, "send");
	n = kget();
	flen = n ? n->nlmsg_len : 0;
	if (n)
		memcpy(first, n, flen);
	for (i = 1; i <= XFRM_EBUSY_RETRIES; i++) {
		kput(k_req, buf, mk_err(buf, 0x4000200, PORTID, EBUSY,
		    XFRM_MSG_DELSA));
		memset(&rc, 0, sizeof(rc));
		rc.so = rcm.so;
		r = rcpfk_handler(&rc);
		CHECK(r == 0, "EBUSY #%d is retried, not an error", i);
		n = kget();
		CHECK(n && n->nlmsg_len == flen && memcmp(n, first, flen) == 0,
		    "retry #%d resends the identical request", i);
	}
	kput(k_req, buf, mk_err(buf, 0x4000200, PORTID, EBUSY, XFRM_MSG_DELSA));
	memset(&rc, 0, sizeof(rc));
	rc.so = rcm.so;
	r = rcpfk_handler(&rc);
	CHECK(r == -1 && rc.eno == EBUSY, "EBUSY after %d retries is an error",
	    XFRM_EBUSY_RETRIES);
	CHECK(kget() == NULL, "no 4th resend");
	CHECK(xfrm_stat_ebusy_retry == XFRM_EBUSY_RETRIES, "retry count %lu",
	    xfrm_stat_ebusy_retry);
}

/*
 * spmd sends SPDGET then reads "the reply".  A foreign multicast policy
 * event queued first must not be parsed into rc (old single-socket bug),
 * a stale unicast reply must be dropped, and our own echo must not fire
 * cb_spdadd.
 */
static void
test_interleaved_waitreply(void)
{
	struct rcpfk_msg rc;
	char buf[512];
	struct sockaddr_in *sp;
	char a[INET_ADDRSTRLEN];
	int r;

	setup();
	memset(&rc, 0, sizeof(rc));
	rc.so = rcm.so;
	rc.seq = 0x500;
	rc.slid = 0x1234;
	rc.dir = RCT_DIR_OUTBOUND;
	CHECK(rcpfk_send_spdget(&rc) == 0, "send spdget");
	(void)kget();
	/* foreign event first (other daemon, pid 999), and our echo */
	kput(k_ntf, buf, mk_policy(buf, XFRM_MSG_NEWPOLICY, 77, 999,
	    "203.0.113.9", "203.0.113.0", 0));
	kput(k_ntf, buf, mk_policy(buf, XFRM_MSG_UPDPOLICY, 0x4ff, PORTID,
	    "198.51.100.1", "198.51.100.0", 0));
	/* stale reply to an old request, then the real reply + ACK */
	kput(k_req, buf, mk_policy(buf, XFRM_MSG_NEWPOLICY, 0x3ff, PORTID,
	    "192.0.2.250", "192.0.2.0", 0));
	kput(k_req, buf, mk_policy(buf, XFRM_MSG_NEWPOLICY, 0x500, PORTID,
	    "10.1.1.1", "10.2.2.0", 0));
	kput(k_req, buf, mk_err(buf, 0x500, PORTID, 0, XFRM_MSG_GETPOLICY));
	rc.flags |= PFK_FLAG_WAITREPLY;
	r = rcpfk_handler(&rc);
	CHECK(r == 0, "WAITREPLY returns the reply: %s", rc.estr);
	sp = (void *)rc.sp_src;
	CHECK(sp != NULL, "sp_src filled from the reply");
	if (sp) {
		inet_ntop(AF_INET, &sp->sin_addr, a, sizeof(a));
		CHECK(strcmp(a, "10.1.1.1") == 0,
		    "rc holds the SPDGET reply, not an event (got %s)", a);
	}
	CHECK(xfrm_stat_stale_reply == 1, "stale reply dropped (%lu)",
	    xfrm_stat_stale_reply);
	CHECK(n_spdadd == 0 && n_spdupd == 0,
	    "events not dispatched during WAITREPLY");
	/* next select() round: the foreign event is delivered, our echo isn't */
	memset(&rc, 0, sizeof(rc));
	rc.so = rcm.so;
	r = rcpfk_handler(&rc);
	CHECK(r == 0, "event round");
	CHECK(n_spdadd == 1, "foreign NEWPOLICY event delivered (%d)", n_spdadd);
	CHECK(n_spdupd == 0, "own UPDPOLICY echo suppressed (%d)", n_spdupd);
	CHECK((last.flags & PFK_FLAG_EVENT) != 0, "event flagged");
}

/* WAITREPLY must not hang when the reply is an error */
static void
test_waitreply_error(void)
{
	struct rcpfk_msg rc;
	char buf[256];

	setup();
	memset(&rc, 0, sizeof(rc));
	rc.so = rcm.so;
	rc.seq = 0x600;
	rc.slid = 9;
	CHECK(rcpfk_send_spdget(&rc) == 0, "send");
	(void)kget();
	kput(k_req, buf, mk_err(buf, 0x600, PORTID, ENOENT, XFRM_MSG_GETPOLICY));
	rc.flags |= PFK_FLAG_WAITREPLY;
	CHECK(rcpfk_handler(&rc) == -1 && rc.eno == ENOENT,
	    "SPDGET ENOENT reported (eno %d)", rc.eno);
}

/*
 * Two requests in flight: the failure of the FIRST arrives after the
 * second was sent.  It must be surfaced (counted + logged), never dropped
 * as a stale reply, and must not complete or abort the second's wait.
 */
static void
test_late_error_not_lost(void)
{
	struct rcpfk_msg rc;
	char buf[256];

	setup();
	memset(&rc, 0, sizeof(rc));
	rc.so = rcm.so;
	rc.seq = 0x700;
	rc.slid = 7;
	CHECK(rcpfk_send_spdget(&rc) == 0, "send 1");
	(void)kget();
	rc.seq = 0x701;
	CHECK(rcpfk_send_spdget(&rc) == 0, "send 2");
	(void)kget();
	kput(k_req, buf, mk_err(buf, 0x700, PORTID, EINVAL, XFRM_MSG_GETPOLICY));
	kput(k_req, buf, mk_err(buf, 0x701, PORTID, ENOENT, XFRM_MSG_GETPOLICY));
	rc.flags |= PFK_FLAG_WAITREPLY;
	CHECK(rcpfk_handler(&rc) == -1 && rc.eno == ENOENT,
	    "wait for seq 0x701 gets ITS error (eno %d)", rc.eno);
	CHECK(xfrm_stat_late_error == 1, "seq 0x700 EINVAL surfaced (%lu)",
	    xfrm_stat_late_error);
	CHECK(xfrm_stat_stale_reply == 0, "and not counted as stale (%lu)",
	    xfrm_stat_stale_reply);
}

/*
 * Netlink aligns messages to 4 bytes only: in one datagram a 20-byte
 * NLMSG_NOOP puts the following policy at 4 mod 8, where the __u64
 * members of xfrm_userpolicy_info are misaligned (UBSan in the live ASan
 * rows).  The library must handle it from an aligned copy.
 */
static void
test_misaligned_batch(void)
{
	union { uint64_t a; char b[1024]; } dg, pol;
	struct nlmsghdr *n = (void *)dg.b;
	struct rcpfk_msg rc;
	struct sockaddr_in *sp;
	char a[INET_ADDRSTRLEN];
	size_t pl;

	setup();
	memset(&dg, 0, sizeof(dg));
	n->nlmsg_len = NLMSG_LENGTH(4);		/* 20: next message at 4 mod 8 */
	n->nlmsg_type = NLMSG_NOOP;
	pl = mk_policy(pol.b, XFRM_MSG_NEWPOLICY, 78, 999,
	    "203.0.113.7", "203.0.113.0", 0);
	memcpy(dg.b + NLMSG_ALIGN(n->nlmsg_len), pol.b, pl);
	kput(k_ntf, dg.b, NLMSG_ALIGN(n->nlmsg_len) + pl);
	memset(&rc, 0, sizeof(rc));
	rc.so = rcm.so;
	CHECK(rcpfk_handler(&rc) == 0, "batch handled: %s", rc.estr);
	CHECK(n_spdadd == 1, "misaligned NEWPOLICY delivered (%d)", n_spdadd);
	/* last is a copy: read its storage, the pointer was the scratch's */
	CHECK(last.sp_src != NULL, "sp_src filled");
	sp = (void *)&last.sp_src_storage;
	inet_ntop(AF_INET, &sp->sin_addr, a, sizeof(a));
	CHECK(strcmp(a, "203.0.113.7") == 0, "policy src %s", a);
}

/* "kernel" thread answering dump requests on the request socket */
static volatile int kthr_stop;
static int kthr_spd, kthr_sa;

static void *
kthr(void *arg)
{
	char in[XFRM_BUFLEN], out[1024];
	struct nlmsghdr *n = (void *)in;
	struct pollfd pfd;

	(void)arg;
	while (!kthr_stop) {
		pfd.fd = k_req;
		pfd.events = POLLIN;
		if (poll(&pfd, 1, 50) <= 0)
			continue;
		if (recv(k_req, in, sizeof(in), 0) < (ssize_t)sizeof(*n))
			continue;
		if (!(n->nlmsg_flags & NLM_F_DUMP))
			continue;
		if (n->nlmsg_type == XFRM_MSG_GETPOLICY) {
			kthr_spd++;
			kput(k_req, out, mk_policy(out, XFRM_MSG_NEWPOLICY,
			    n->nlmsg_seq, PORTID, "10.0.0.1", "10.0.1.0",
			    NLM_F_MULTI));
			kput(k_req, out, mk_done(out, n->nlmsg_seq, PORTID));
		} else if (n->nlmsg_type == XFRM_MSG_GETSA) {
			kthr_sa++;
			kput(k_req, out, mk_sa(out, XFRM_MSG_NEWSA, n->nlmsg_seq,
			    PORTID, 0xa1, NLM_F_MULTI));
			kput(k_req, out, mk_sa(out, XFRM_MSG_NEWSA, n->nlmsg_seq,
			    PORTID, 0xa2, NLM_F_MULTI));
			kput(k_req, out, mk_done(out, n->nlmsg_seq, PORTID));
		}
	}
	return NULL;
}

/* "kernel" without CONFIG_XFRM_MIGRATE: MIGRATE -> ENOPROTOOPT, then
 * serve the GETSA dump (one UDP-encapsulated SA) and check the UPDSA */
static volatile int mthr_stop;
static int mthr_migrate, mthr_dump, mthr_upd;
static unsigned mthr_upd_sport, mthr_upd_dport;

static void *
mthr(void *arg)
{
	union { uint64_t a; char b[XFRM_BUFLEN]; } in, out;
	struct nlmsghdr *n = (void *)in.b;
	struct pollfd pfd;

	(void)arg;
	while (!mthr_stop) {
		pfd.fd = k_req;
		pfd.events = POLLIN;
		if (poll(&pfd, 1, 50) <= 0)
			continue;
		if (recv(k_req, in.b, sizeof(in.b), 0) < (ssize_t)sizeof(*n))
			continue;
		if (n->nlmsg_type == XFRM_MSG_MIGRATE) {
			mthr_migrate++;
			kput(k_req, out.b, mk_err(out.b, n->nlmsg_seq, PORTID,
			    ENOPROTOOPT, XFRM_MSG_MIGRATE));
		} else if (n->nlmsg_type == XFRM_MSG_GETSA &&
		    (n->nlmsg_flags & NLM_F_DUMP)) {
			struct nlmsghdr *o = (void *)out.b;
			struct rtattr *rta;
			struct xfrm_encap_tmpl et;
			size_t l;

			mthr_dump++;
			/* a non-matching SA, then ours with encap 4500/4500 */
			l = mk_sa(out.b, XFRM_MSG_NEWSA, n->nlmsg_seq, PORTID,
			    0xb0, NLM_F_MULTI);
			((struct xfrm_usersa_info *)NLMSG_DATA(o))->id.daddr.a4 =
			    htonl(0xc0000263);	/* 192.0.2.99 */
			kput(k_req, out.b, l);
			l = mk_sa(out.b, XFRM_MSG_NEWSA, n->nlmsg_seq, PORTID,
			    0xb1, NLM_F_MULTI);
			memset(&et, 0, sizeof(et));
			et.encap_type = UDP_ENCAP_ESPINUDP;
			et.encap_sport = htons(4500);
			et.encap_dport = htons(4500);
			rta = (struct rtattr *)(out.b + NLMSG_ALIGN(l));
			rta->rta_type = XFRMA_ENCAP;
			rta->rta_len = RTA_LENGTH(sizeof(et));
			memcpy(RTA_DATA(rta), &et, sizeof(et));
			o->nlmsg_len = NLMSG_ALIGN(l) + RTA_ALIGN(rta->rta_len);
			kput(k_req, out.b, o->nlmsg_len);
			kput(k_req, out.b, mk_done(out.b, n->nlmsg_seq, PORTID));
		} else if (n->nlmsg_type == XFRM_MSG_UPDSA) {
			struct rtattr *rta = (struct rtattr *)((char *)NLMSG_DATA(n)
			    + NLMSG_ALIGN(sizeof(struct xfrm_usersa_info)));
			int alen = (int)n->nlmsg_len -
			    (int)NLMSG_LENGTH(sizeof(struct xfrm_usersa_info));

			mthr_upd++;
			for (; RTA_OK(rta, alen); rta = RTA_NEXT(rta, alen)) {
				struct xfrm_encap_tmpl et;

				if (rta->rta_type != XFRMA_ENCAP)
					continue;
				memcpy(&et, RTA_DATA(rta), sizeof(et));
				mthr_upd_sport = ntohs(et.encap_sport);
				mthr_upd_dport = ntohs(et.encap_dport);
			}
			kput(k_req, out.b, mk_err(out.b, n->nlmsg_seq, PORTID, 0,
			    XFRM_MSG_UPDSA));
		}
	}
	return NULL;
}

static void
test_migrate_port_only_without_migrate(void)
{
	struct rcpfk_msg rc;
	struct sockaddr_in s, d, s2, d2;
	pthread_t th;
	int r;

	setup();
	memset(&rc, 0, sizeof(rc));
	rc.so = rcm.so;
	memset(&s, 0, sizeof(s));
	s.sin_family = AF_INET;
	inet_pton(AF_INET, "192.0.2.1", &s.sin_addr);
	s.sin_port = htons(4500);
	d = s;
	inet_pton(AF_INET, "192.0.2.2", &d.sin_addr);
	s2 = s;
	d2 = d;
	d2.sin_port = htons(40028);		/* the NAT re-mapped the port */
	rc.sa_src = (void *)&s;
	rc.sa_dst = (void *)&d;
	rc.sa2_src = (void *)&s2;
	rc.sa2_dst = (void *)&d2;
	rc.sp_src = (void *)&s;
	rc.sp_dst = (void *)&d;
	rc.pref_src = rc.pref_dst = 32;
	rc.satype = RCT_SATYPE_ESP;
	rc.samode = RCT_IPSM_TRANSPORT;
	rc.dir = RCT_DIR_OUTBOUND;
	rc.natt_type = UDP_ENCAP_ESPINUDP;
	rc.natt_sport = htons(4500);
	rc.natt_dport = htons(40028);
	mthr_stop = 0;
	mthr_migrate = mthr_dump = mthr_upd = 0;
	pthread_create(&th, NULL, mthr, NULL);
	r = rcpfk_send_migrate(&rc);
	CHECK(r == 0, "port-only move applied without MIGRATE: %s", rc.estr);
	CHECK(mthr_migrate == 1 && mthr_dump == 1 && mthr_upd == 1,
	    "MIGRATE tried, SA dumped, ONE UPDSA (m=%d d=%d u=%d)",
	    mthr_migrate, mthr_dump, mthr_upd);
	CHECK(mthr_upd_sport == 4500 && mthr_upd_dport == 40028,
	    "UPDSA encap %u -> %u", mthr_upd_sport, mthr_upd_dport);
	/* an ADDRESS change cannot be done without MIGRATE: error, no UPDSA */
	inet_pton(AF_INET, "192.0.2.77", &d2.sin_addr);
	mthr_migrate = mthr_dump = mthr_upd = 0;
	r = rcpfk_send_migrate(&rc);
	CHECK(r == -1 && rc.eno == ENOPROTOOPT,
	    "address move fails loudly (r=%d eno=%d: %s)", r, rc.eno, rc.estr);
	CHECK(mthr_upd == 0 && mthr_dump == 0, "no UPDSA for an address move");
	mthr_stop = 1;
	pthread_join(th, NULL);
}

static void
test_enobufs_resync(void)
{
	struct rcpfk_msg rc;
	char buf[1024];
	struct nlmsghdr *n;
	int r, saw_spd = 0, saw_sa = 0;

	setup();
	/* a pending GETSPI whose reply will be lost with the request socket */
	{
		struct sockaddr_in s, d;

		fill_sa_rc(&rc, &s, &d, 0x4000700, 0);
		CHECK(rcpfk_send_getspi(&rc) == 0, "getspi");
		(void)kget();
	}
	{
		pthread_t th;

		kthr_stop = 0;
		kthr_spd = kthr_sa = 0;
		dump_flag_ok = 1;
		if (pthread_create(&th, NULL, kthr, NULL) != 0)
			exit(99);
		pthread_detach(th);
	}
	/* an event that survived the overflow */
	kput(k_ntf, buf, mk_policy(buf, XFRM_MSG_NEWPOLICY, 5, 999,
	    "203.0.113.1", "203.0.113.0", 0));
	xfrm_test_enobufs_fd = xfrm_ntf_fd;
	memset(&rc, 0, sizeof(rc));
	rc.so = rcm.so;
	r = rcpfk_handler(&rc);
	CHECK(r == 0, "handler survives ENOBUFS: %s", rc.estr);
	CHECK(xfrm_stat_enobufs == 1 && xfrm_stat_resync == 1,
	    "ENOBUFS counted and resynced (%lu/%lu)", xfrm_stat_enobufs,
	    xfrm_stat_resync);
	CHECK(n_spdadd == 1, "surviving event still drained and delivered");
	CHECK(n_spddump == 1, "SPD dump delivered (%d)", n_spddump);
	CHECK(dump_flag_ok, "dumped SA/SP flagged PFK_FLAG_RESYNC");
	CHECK(n_sadump == 2, "two SAs delivered to cb_sadump (%d)", n_sadump);
	CHECK(n_resync == 1, "cb_resync once (%d)", n_resync);
	CHECK(resync_sa_seq == 0 && resync_spd_seq == 0, "dumps finished");
	saw_spd = kthr_spd;
	saw_sa = kthr_sa;
	(void)n;
	CHECK(saw_spd == 1 && saw_sa == 1, "dump requests sent on the request "
	    "socket (spd %d sa %d)", saw_spd, saw_sa);
	CHECK(xfrm_nops == 1 && op_find(0x4000700) != NULL &&
	    op_find(0x4000700)->type == XFRM_MSG_ALLOCSPI,
	    "notify overflow leaves the request-socket op pending");

	/* now the request socket overflows: its pending op is dropped */
	xfrm_test_enobufs_fd = xfrm_req_fd;
	memset(&rc, 0, sizeof(rc));
	rc.so = rcm.so;
	r = rcpfk_handler(&rc);
	CHECK(r == 0, "request-socket ENOBUFS handled: %s", rc.estr);
	CHECK(xfrm_nops == 0 && op_find(0x4000700) == NULL,
	    "stranded pending op dropped");
	CHECK(xfrm_stat_resync == 2 && n_resync == 2, "second resync (%lu)",
	    xfrm_stat_resync);
	kthr_stop = 1;
	usleep(120000);
}

static void
test_mapping_migrate_fresh(void)
{
	char buf[1024];
	struct nlmsghdr *n = (void *)buf;
	struct xfrm_user_mapping *um;
	struct rcpfk_msg rc;
	struct sockaddr_in *ns;
	size_t off;
	int r;

	setup();
	/* one datagram: MAPPING then ACQUIRE (fresh container per msg) */
	memset(buf, 0, sizeof(buf));
	n->nlmsg_len = NLMSG_LENGTH(sizeof(*um));
	n->nlmsg_type = XFRM_MSG_MAPPING;
	um = NLMSG_DATA(n);
	um->id.family = AF_INET;
	um->id.proto = IPPROTO_ESP;
	um->id.spi = htonl(0xc0ffee);
	v4(&um->id.daddr, "192.0.2.2");
	v4(&um->old_saddr, "198.51.100.7");
	v4(&um->new_saddr, "198.51.100.7");
	um->old_sport = htons(4500);
	um->new_sport = htons(31337);
	um->reqid = 7;
	off = NLMSG_ALIGN(n->nlmsg_len);
	{
		struct nlmsghdr *a = (void *)(buf + off);
		struct xfrm_user_acquire *ac;
		struct rtattr *rta;
		struct xfrm_user_tmpl *t;

		a->nlmsg_len = NLMSG_LENGTH(sizeof(*ac)) +
		    RTA_LENGTH(sizeof(*t));
		a->nlmsg_type = XFRM_MSG_ACQUIRE;
		ac = NLMSG_DATA(a);
		ac->sel.family = AF_INET;
		v4(&ac->sel.saddr, "10.0.0.1");
		v4(&ac->sel.daddr, "10.0.1.1");
		rta = (void *)((char *)ac + NLMSG_ALIGN(sizeof(*ac)));
		rta->rta_type = XFRMA_TMPL;
		rta->rta_len = RTA_LENGTH(sizeof(*t));
		t = RTA_DATA(rta);
		t->family = AF_INET;
		t->id.proto = IPPROTO_ESP;
		v4(&t->saddr, "192.0.2.1");
		v4(&t->id.daddr, "192.0.2.2");
		off += NLMSG_ALIGN(a->nlmsg_len);
	}
	kput(k_ntf, buf, off);
	memset(&rc, 0, sizeof(rc));
	rc.so = rcm.so;
	r = rcpfk_handler(&rc);
	CHECK(r == 0, "mapping round: %s", rc.estr);
	CHECK(n_mapping == 1, "cb_mapping fired (%d)", n_mapping);
	ns = (void *)last.sa2_src;
	(void)ns;
	CHECK(n_acquire == 1, "acquire in same datagram delivered");
	CHECK(!acquire_saw_sa2,
	    "MAPPING's sa2_src did not leak into the ACQUIRE container");

	/* check the mapping contents with a lone MAPPING */
	kput(k_ntf, buf, NLMSG_ALIGN(n->nlmsg_len));
	reset_counts();
	memset(&rc, 0, sizeof(rc));
	rc.so = rcm.so;
	(void)rcpfk_handler(&rc);
	CHECK(n_mapping == 1, "lone mapping");
	CHECK(last.spi == htonl(0xc0ffee) && last.reqid == 7 &&
	    last.satype == RCT_SATYPE_ESP, "mapping spi/reqid/satype");
	CHECK(last.natt_dport == htons(31337), "new NAT-T port %u",
	    ntohs(last.natt_dport));

#ifdef SADB_X_MIGRATE
	{
		struct xfrm_userpolicy_id *id;
		struct rtattr *rta;
		struct xfrm_user_migrate *m;

		memset(buf, 0, sizeof(buf));
		n->nlmsg_len = NLMSG_LENGTH(sizeof(*id)) + RTA_LENGTH(sizeof(*m));
		n->nlmsg_type = XFRM_MSG_MIGRATE;
		n->nlmsg_pid = 31;	/* another KM */
		id = NLMSG_DATA(n);
		id->dir = XFRM_POLICY_OUT;
		id->sel.family = AF_INET;
		rta = (void *)((char *)id + NLMSG_ALIGN(sizeof(*id)));
		rta->rta_type = XFRMA_MIGRATE;
		rta->rta_len = RTA_LENGTH(sizeof(*m));
		m = RTA_DATA(rta);
		m->proto = IPPROTO_ESP;
		m->mode = XFRM_MODE_TUNNEL;
		m->reqid = 9;
		m->old_family = m->new_family = AF_INET;
		v4(&m->old_saddr, "192.0.2.1");
		v4(&m->old_daddr, "192.0.2.2");
		v4(&m->new_saddr, "192.0.2.11");
		v4(&m->new_daddr, "192.0.2.2");
		kput(k_ntf, buf, n->nlmsg_len);
		/* and our own migrate's echo, which must not be delivered */
		n->nlmsg_pid = PORTID;
		kput(k_ntf, buf, n->nlmsg_len);
		reset_counts();
		memset(&rc, 0, sizeof(rc));
		rc.so = rcm.so;
		(void)rcpfk_handler(&rc);
		CHECK(n_migrate == 1, "foreign MIGRATE delivered once, own echo "
		    "suppressed (%d)", n_migrate);
		CHECK(last.reqid == 9 && last.sa2_src != NULL &&
		    ((struct sockaddr_in *)last.sa2_src)->sin_addr.s_addr ==
		    inet_addr("192.0.2.11"), "migrate new src");
	}
#endif
}

/* short messages are rejected, never read past the end */
static void
test_short_messages(void)
{
	char buf[64];
	struct nlmsghdr *n = (void *)buf;
	struct rcpfk_msg rc;

	setup();
	memset(buf, 0, sizeof(buf));
	n->nlmsg_len = NLMSG_LENGTH(4);
	n->nlmsg_type = XFRM_MSG_MAPPING;
	kput(k_ntf, buf, n->nlmsg_len);
	memset(&rc, 0, sizeof(rc));
	rc.so = rcm.so;
	CHECK(rcpfk_handler(&rc) == -1 && rc.eno == EINVAL,
	    "short MAPPING rejected");
	CHECK(n_mapping == 0, "no callback for a short MAPPING");
	n->nlmsg_type = NLMSG_ERROR;
	n->nlmsg_len = NLMSG_LENGTH(2);
	kput(k_req, buf, n->nlmsg_len);
	memset(&rc, 0, sizeof(rc));
	rc.so = rcm.so;
	(void)rcpfk_handler(&rc);
	CHECK(1, "short NLMSG_ERROR did not crash");
}

static void
test_satype_proto_mapping(void)
{
	/* The centralized RCT_SATYPE<->IPPROTO mapping (lib/rcpfk_util.c) must
	 * be stable and bidirectional for every supported satype, since the
	 * XFRM backend relies on it on both the install and the decode path. */
	static const uint8_t cases[][2] = {
		{ RCT_SATYPE_AH, IPPROTO_AH },
		{ RCT_SATYPE_ESP, IPPROTO_ESP },
		{ RCT_SATYPE_IPCOMP, IPPROTO_IPCOMP },
	};
	size_t i;
	uint8_t p;

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		p = rcpfk_satype_to_proto(cases[i][0]);
		CHECK(p == cases[i][1], "satype %u -> proto %u (want %u)",
		    cases[i][0], p, cases[i][1]);
		CHECK(rcpfk_proto_to_satype(cases[i][1]) == cases[i][0],
		    "proto %u -> satype %u (want %u)",
		    cases[i][1], rcpfk_proto_to_satype(cases[i][1]),
		    cases[i][0]);
	}
	/* unknown proto falls back to ESP, unknown satype to ESP proto */
	CHECK(rcpfk_satype_to_proto(0xff) == IPPROTO_ESP,
	    "unknown satype -> ESP proto");
	CHECK(rcpfk_proto_to_satype(0xff) == RCT_SATYPE_ESP,
	    "unknown proto -> ESP satype");
}

static int
nl_walk_count(struct nlmsghdr *nlh, void *arg)
{
	int *n = arg;

	(void)nlh;
	(*n)++;
	return 0;
}

static int
nl_walk_stop2(struct nlmsghdr *nlh, void *arg)
{
	int *n = arg;

	(void)nlh;
	return ++(*n) == 2 ? 7 : 0;
}

/* rcpfk_nl_recv: every outcome a netlink consumer must tell apart */
static void
test_nl_recv(void)
{
	char big[256], small[32];
	struct nlmsghdr *n = (struct nlmsghdr *)big;
	ssize_t got;
	int p[2], r;

	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, p))
		exit(99);
	fcntl(p[0], F_SETFL, fcntl(p[0], F_GETFL) | O_NONBLOCK);

	r = rcpfk_nl_recv(p[0], small, sizeof(small), 0, &got);
	CHECK(r == RCPFK_NLR_AGAIN && got == 0, "nl_recv: empty -> AGAIN (%d)",
	    r);

	memset(big, 0, sizeof(big));
	n->nlmsg_len = NLMSG_LENGTH(0);
	CHECK(send(p[1], big, NLMSG_LENGTH(0), 0) == NLMSG_LENGTH(0), "send");
	r = rcpfk_nl_recv(p[0], small, sizeof(small), 0, &got);
	CHECK(r == RCPFK_NLR_DATA && got == NLMSG_LENGTH(0),
	    "nl_recv: whole datagram -> DATA (%d, %zd)", r, got);

	/* a datagram bigger than the buffer must NOT look like a short
	 * complete read: the tail (more messages) was dropped */
	CHECK(send(p[1], big, sizeof(big), 0) == (ssize_t)sizeof(big), "send");
	r = rcpfk_nl_recv(p[0], small, sizeof(small), 0, &got);
	CHECK(r == RCPFK_NLR_TRUNC, "nl_recv: oversize datagram -> TRUNC (%d)",
	    r);

	CHECK(send(p[1], big, 4, 0) == 4, "send");
	r = rcpfk_nl_recv(p[0], small, sizeof(small), 0, &got);
	CHECK(r == RCPFK_NLR_SHORT && got == 4, "nl_recv: 4 bytes -> SHORT (%d)",
	    r);

	CHECK(send(p[1], big, 0, 0) == 0, "send");
	r = rcpfk_nl_recv(p[0], small, sizeof(small), 0, &got);
	CHECK(r == RCPFK_NLR_CLOSED, "nl_recv: zero-length -> CLOSED (%d)", r);

	r = rcpfk_nl_recv(-1, small, sizeof(small), 0, &got);
	CHECK(r == RCPFK_NLR_ERROR && errno == EBADF,
	    "nl_recv: bad fd -> ERROR/EBADF (%d)", r);
	close(p[0]);
	close(p[1]);
	CHECK(strcmp(rcpfk_nlr_str(RCPFK_NLR_TRUNC),
	    "datagram truncated (MSG_TRUNC)") == 0, "nlr_str");
}

/* xfrm_sync on an overflowed request socket returns ENOBUFS itself, not
 * whatever errno happens to hold (the injector leaves errno 0) */
static void
test_sync_enobufs(void)
{
	char buf[NLMSG_SPACE(sizeof(struct xfrm_usersa_id))], junk[16];
	struct nlmsghdr *n = (struct nlmsghdr *)buf;
	int e;

	setup();
	memset(buf, 0, sizeof(buf));
	n->nlmsg_len = sizeof(buf);
	n->nlmsg_type = XFRM_MSG_GETSA;
	n->nlmsg_flags = NLM_F_REQUEST;
	memset(junk, 0, sizeof(junk));
	kput(k_req, junk, sizeof(junk));	/* make the request fd readable */
	xfrm_test_enobufs_fd = xfrm_req_fd;
	xfrm_test_enobufs_more = 0;
	e = xfrm_sync(n, NULL, NULL);
	CHECK(e == ENOBUFS, "sync overflow returns ENOBUFS explicitly (%d)", e);
	(void)kget();
}

/* a notification datagram larger than XFRM_RCVBUFLEN lost messages: it is
 * counted, triggers a resync and its surviving head is not delivered */
static void
test_trunc_resync(void)
{
	struct rcpfk_msg rc;
	char *buf;
	size_t blen = XFRM_RCVBUFLEN + 4096;
	int r, sb = (int)(4 * blen);
	pthread_t th;

	setup();
	if ((buf = calloc(1, blen)) == NULL)
		exit(99);
	(void)mk_policy(buf, XFRM_MSG_NEWPOLICY, 5, 999, "203.0.113.1",
	    "203.0.113.0", 0);
	(void)setsockopt(k_ntf, SOL_SOCKET, SO_SNDBUF, &sb, sizeof(sb));
	(void)setsockopt(xfrm_ntf_fd, SOL_SOCKET, SO_RCVBUF, &sb, sizeof(sb));
	if (send(k_ntf, buf, blen, 0) != (ssize_t)blen) {
		/* the host caps socket buffers below one oversize datagram:
		 * the classification itself is pinned by test_nl_recv */
		printf("SKIP trunc_resync: cannot queue a %zu byte datagram: "
		    "%s\n", blen, strerror(errno));
		free(buf);
		return;
	}
	free(buf);
	kthr_stop = 0;
	kthr_spd = kthr_sa = 0;
	dump_flag_ok = 1;
	if (pthread_create(&th, NULL, kthr, NULL) != 0)
		exit(99);
	pthread_detach(th);
	memset(&rc, 0, sizeof(rc));
	rc.so = rcm.so;
	r = rcpfk_handler(&rc);
	CHECK(r == 0, "handler survives a truncated datagram: %s", rc.estr);
	CHECK(xfrm_stat_trunc == 1 && xfrm_stat_enobufs == 0,
	    "truncation counted as truncation (%lu/%lu)", xfrm_stat_trunc,
	    xfrm_stat_enobufs);
	CHECK(xfrm_stat_resync == 1 && n_resync == 1,
	    "truncation resynced (%lu, %d)", xfrm_stat_resync, n_resync);
	CHECK(n_spdadd == 0, "truncated head not delivered (%d)", n_spdadd);
	CHECK(n_spddump == 1, "SPD state re-established by dump (%d)",
	    n_spddump);
	kthr_stop = 1;
	usleep(120000);
}

static void
test_nl_walk(void)
{
	char buf[128];
	struct nlmsghdr *n;
	int cnt;

	/* one valid message: buflen == NLMSG_LENGTH(0), dispatched, rc 0 */
	memset(buf, 0, sizeof(buf));
	n = (struct nlmsghdr *)buf;
	n->nlmsg_len = NLMSG_LENGTH(0);
	cnt = 0;
	CHECK(rcpfk_nl_walk(buf, (size_t)NLMSG_LENGTH(0), nl_walk_count,
	    &cnt) == 0, "nl_walk: single valid message returns 0");
	CHECK(cnt == 1, "nl_walk: one message dispatched");

	/* a valid 16-byte message followed by a trailer whose nlmsg_len
	 * claims 64 with only 16 bytes present: malformed, rc -1, first
	 * message still dispatched, trailer NOT */
	memset(buf, 0, sizeof(buf));
	n = (struct nlmsghdr *)buf;
	n->nlmsg_len = sizeof(struct nlmsghdr);
	((struct nlmsghdr *)(buf + NLMSG_ALIGN((int)sizeof(struct nlmsghdr))))
	    ->nlmsg_len = 64;
	cnt = 0;
	CHECK(rcpfk_nl_walk(buf, sizeof(struct nlmsghdr) * 2, nl_walk_count,
	    &cnt) == -1, "nl_walk: truncated trailer -> -1");
	CHECK(cnt == 1, "nl_walk: truncated trailer stopped after 1");

	/* nlmsg_len == 0 is malformed (not a silent success, and not dispatched) */
	memset(buf, 0, sizeof(buf));
	cnt = 0;
	CHECK(rcpfk_nl_walk(buf, sizeof(struct nlmsghdr), nl_walk_count,
	    &cnt) == -1, "nl_walk: nlmsg_len==0 -> -1");
	CHECK(cnt == 0, "nl_walk: nlmsg_len==0 did not dispatch");

	/* a buffer shorter than a header is malformed, not dispatched */
	cnt = 0;
	CHECK(rcpfk_nl_walk(buf, sizeof(struct nlmsghdr) - 1, nl_walk_count,
	    &cnt) == -1, "nl_walk: short buffer -> -1");
	CHECK(cnt == 0, "nl_walk: short buffer did not dispatch");

	/* alignment-only tail after a real message is a normal end (rc 0) */
	memset(buf, 0, sizeof(buf));
	n = (struct nlmsghdr *)buf;
	n->nlmsg_len = sizeof(struct nlmsghdr);
	cnt = 0;
	CHECK(rcpfk_nl_walk(buf, sizeof(struct nlmsghdr) + 2, nl_walk_count,
	    &cnt) == 0, "nl_walk: trailing padding returns 0");
	CHECK(cnt == 1, "nl_walk: padding did not dispatch");

	CHECK(rcpfk_abi_version() == RCPFK_ABI_VERSION,
	    "rcpfk_abi_version() matches the header RCPFK_ABI_VERSION");

	/* a valid message followed by a truncated next header (8 of 16 bytes
	 * present) is malformed, NOT silent alignment padding (padding is 0-3) */
	memset(buf, 0, sizeof(buf));
	n = (struct nlmsghdr *)buf;
	n->nlmsg_len = sizeof(struct nlmsghdr);
	((struct nlmsghdr *)(buf + NLMSG_ALIGN((int)sizeof(struct nlmsghdr))))
	    ->nlmsg_len = 8;
	cnt = 0;
	CHECK(rcpfk_nl_walk(buf, sizeof(struct nlmsghdr) + 8, nl_walk_count,
	    &cnt) == -1, "nl_walk: truncated next header (8B) -> -1");
	CHECK(cnt == 1, "nl_walk: truncated next header stopped after 1");

	/* a callback's > 0 return stops the walk early with that value */
	memset(buf, 0, sizeof(buf));
	for (cnt = 0; cnt < 3; cnt++)
		((struct nlmsghdr *)(buf + cnt * NLMSG_LENGTH(0)))->nlmsg_len =
		    NLMSG_LENGTH(0);
	cnt = 0;
	CHECK(rcpfk_nl_walk(buf, 3 * NLMSG_LENGTH(0), nl_walk_stop2, &cnt) == 7,
	    "nl_walk: callback stop value returned");
	CHECK(cnt == 2, "nl_walk: stopped after the 2nd message (%d)", cnt);
}

static void
test_fill_selector(void)
{
	struct xfrm_selector sel;
	struct sockaddr_in s4, d4;
	struct sockaddr_in6 d6, d6spec;
	int r;

	/* v4-src + v6-:: wildcard must coerce to an AF_INET selector (the garble
	 * xfrmtmpl catches on the SA path; fill_selector is shared with the
	 * policy path, so pin it here without touching the kernel) */
	memset(&s4, 0, sizeof(s4));
	s4.sin_family = AF_INET;
	((unsigned char *)&s4.sin_addr.s_addr)[0] = 192;
	((unsigned char *)&s4.sin_addr.s_addr)[1] = 0;
	((unsigned char *)&s4.sin_addr.s_addr)[2] = 2;
	((unsigned char *)&s4.sin_addr.s_addr)[3] = 1;
	memset(&d6, 0, sizeof(d6));
	d6.sin6_family = AF_INET6;	/* :: unspecified */
	r = fill_selector(&sel, (struct sockaddr *)&s4, (struct sockaddr *)&d6,
	    32, 0, RC_PROTO_ANY, 0);
	CHECK(r == 0, "fill_selector: v4-src + v6-:: returns 0");
	CHECK(sel.family == AF_INET,
	    "fill_selector: v4-src + v6-:: coerces to AF_INET (got %u)",
	    sel.family);
	CHECK(sel.daddr.a4 == 0, "fill_selector: :: coerced to v4-any");

	/* a genuinely mixed SPECIFIED pair is rejected, not garbled */
	memset(&d6spec, 0, sizeof(d6spec));
	d6spec.sin6_family = AF_INET6;
	d6spec.sin6_addr.s6_addr[0] = 0x20;
	d6spec.sin6_addr.s6_addr[1] = 0x01;
	d6spec.sin6_addr.s6_addr[2] = 0x0d;
	d6spec.sin6_addr.s6_addr[3] = 0xb8;
	d6spec.sin6_addr.s6_addr[15] = 0x01;	/* 2001:db8::1 */
	r = fill_selector(&sel, (struct sockaddr *)&s4, (struct sockaddr *)&d6spec,
	    32, 128, RC_PROTO_ANY, 0);
	CHECK(r == -1, "fill_selector: mixed SPECIFIED pair rejected");

	/* same-family v4+v4 stays AF_INET with the requested proto */
	memset(&d4, 0, sizeof(d4));
	d4.sin_family = AF_INET;
	((unsigned char *)&d4.sin_addr.s_addr)[3] = 2;	/* 0.0.0.2 */
	r = fill_selector(&sel, (struct sockaddr *)&s4, (struct sockaddr *)&d4,
	    32, 32, IPPROTO_ESP, 0);
	CHECK(r == 0 && sel.family == AF_INET && sel.proto == IPPROTO_ESP,
	    "fill_selector: v4+v4 AF_INET proto esp");
}

static int
offload_rta_get(const char *buf, size_t len, size_t pay_off, int type,
    const void **data, size_t *dlen)
{
	const struct rtattr *rta;
	size_t base = NLMSG_ALIGN(sizeof(struct nlmsghdr) + pay_off);
	size_t rem = len - base;

	/* RTA_OK/RTA_NEXT, not a hand-rolled cursor: a comma stepper that
	 * advances by RTA_ALIGN(rta_len) never terminates once a trailing
	 * zeroed (rta_len==0) region is reached — it hung here. pay_off is the
	 * fixed payload struct between the nlmsghdr and the rtattrs (0 for a
	 * bare header). */
	for (rta = (const void *)(buf + base);
	     RTA_OK(rta, rem);
	     rta = RTA_NEXT(rta, rem)) {
		if (rta->rta_type == type) {
			if (data)
				*data = RTA_DATA(rta);
			if (dlen)
				*dlen = RTA_PAYLOAD(rta);
			return 1;
		}
	}
	return 0;
}

static void
test_offload_attrs(void)
{
	char buf[512];
	struct nlmsghdr *n;
	struct rcpfk_msg rc;
	const void *d;
	size_t dl, len;

	/* positive: mark + if_id + an OUTBOUND offload (flags==0, ifindex 5)
	 * must ALL be emitted — the wire-bytes pin that proves offload is
	 * actually on the wire (not compiled out, which is what the old
	 * #ifdef-on-an-enum guard did) */
	memset(buf, 0, sizeof(buf));
	memset(&rc, 0, sizeof(rc));
	n = (struct nlmsghdr *)buf;
	n->nlmsg_len = NLMSG_LENGTH(0);
	rc.mark = 0x100;
	rc.mark_mask = 0xff;
	rc.if_id = 1;
	rc.offload_ifindex = 5;
	rc.offload_flags = 0;	/* outbound — must still be emitted */
	rc.satype = RCT_SATYPE_ESP;	/* device offload is ESP-only */
	CHECK(add_xfrm_mark_ifid_attrs(n, sizeof(buf), &rc) == 0,
	    "offload: mark/if_id attrs appended");
	CHECK(add_xfrm_offload_attr(n, sizeof(buf), &rc) == 0,
	    "offload: offload attr appended (flags=0 outbound)");
	len = n->nlmsg_len;

	CHECK(offload_rta_get(buf, len, 0, XFRMA_MARK, &d, &dl) == 1 &&
	    dl == sizeof(struct xfrm_mark) &&
	    ((const struct xfrm_mark *)d)->v == (0x100 & 0xff) &&
	    ((const struct xfrm_mark *)d)->m == 0xff,
	    "offload: XFRMA_MARK v/m emitted (v masked by m)");
	CHECK(offload_rta_get(buf, len, 0, XFRMA_IF_ID, &d, &dl) == 1 &&
	    dl == 4 && *(const unsigned int *)d == 1,
	    "offload: XFRMA_IF_ID emitted");
	CHECK(offload_rta_get(buf, len, 0, XFRMA_OFFLOAD_DEV, &d, &dl) == 1 &&
	    dl == sizeof(struct xfrm_user_offload) &&
	    ((const struct xfrm_user_offload *)d)->ifindex == 5 &&
	    ((const struct xfrm_user_offload *)d)->flags == 0,
	    "offload: XFRMA_OFFLOAD_DEV ifindex/flags(outbound) emitted");

	/* negative: an AH (or IPComp) state with a device is refused by the
	 * emitter itself, not only by today's ESP-filtering caller */
	memset(buf, 0, sizeof(buf));
	memset(&rc, 0, sizeof(rc));
	n = (struct nlmsghdr *)buf;
	n->nlmsg_len = NLMSG_LENGTH(0);
	rc.offload_ifindex = 5;
	rc.satype = RCT_SATYPE_AH;
	CHECK(add_xfrm_offload_attr(n, sizeof(buf), &rc) == -1 &&
	    rc.eno == EINVAL, "offload: AH + device refused EINVAL (eno %d)",
	    rc.eno);
	CHECK(n->nlmsg_len == NLMSG_LENGTH(0), "offload: nothing appended "
	    "for AH");
	rc.satype = RCT_SATYPE_IPCOMP;
	rc.eno = 0;
	CHECK(add_xfrm_offload_attr(n, sizeof(buf), &rc) == -1 &&
	    rc.eno == EINVAL, "offload: IPComp + device refused EINVAL");

	/* negative: mask 0 + if_id 0 + no device -> NO attrs at all */
	memset(buf, 0, sizeof(buf));
	memset(&rc, 0, sizeof(rc));
	n = (struct nlmsghdr *)buf;
	n->nlmsg_len = NLMSG_LENGTH(0);
	rc.mark = 0x100;	/* value set but mask 0 -> not requested */
	CHECK(add_xfrm_mark_ifid_attrs(n, sizeof(buf), &rc) == 0,
	    "offload: no mark/if_id when mask/if_id 0");
	CHECK(add_xfrm_offload_attr(n, sizeof(buf), &rc) == 0,
	    "offload: no offload attr when no device named");
	len = n->nlmsg_len;
	CHECK(offload_rta_get(buf, len, 0, XFRMA_MARK, NULL, NULL) == 0 &&
	    offload_rta_get(buf, len, 0, XFRMA_IF_ID, NULL, NULL) == 0 &&
	    offload_rta_get(buf, len, 0, XFRMA_OFFLOAD_DEV, NULL, NULL) == 0,
	    "offload: mask0/ifid0/no-device emits no XFRMA attrs");

	/* negative: a bad device NAME -> add_xfrm_offload_attr fails (ENODEV),
	 * never a silent no-offload SA */
	memset(buf, 0, sizeof(buf));
	memset(&rc, 0, sizeof(rc));
	n = (struct nlmsghdr *)buf;
	n->nlmsg_len = NLMSG_LENGTH(0);
	snprintf(rc.offload_ifname, sizeof(rc.offload_ifname),
	    "__definitely_not_a_device__");
	rc.satype = RCT_SATYPE_ESP;
	CHECK(add_xfrm_offload_attr(n, sizeof(buf), &rc) == -1 &&
	    rc.eno == ENODEV,
	    "offload: unresolvable device name -> refuse (ENODEV, got %d)",
	    rc.eno);
}

static void
test_mark_emit_live_paths(void)
{
	struct rcpfk_msg rc;
	struct sockaddr_in s, d;
	struct nlmsghdr *n;
	const void *dd;
	size_t dl;

	/* ALLOCSPI: the larval for a marked child SA must carry XFRMA_MARK or
	 * the later UPDSA cannot match it (larval mark 0 vs UPDSA mark). */
	setup();
	fill_sa_rc(&rc, &s, &d, 0x4010000, 0);
	rc.so = rcm.so;
	rc.mark = 0x100; rc.mark_mask = 0xff;
	rc.if_id = 7;
	CHECK(rcpfk_send_getspi(&rc) == 0, "getspi: %s", rc.estr);
	n = kget();
	CHECK(n && n->nlmsg_type == XFRM_MSG_ALLOCSPI,
	    "ALLOCSPI on req socket");
	CHECK(n && offload_rta_get((const char *)n, n->nlmsg_len,
	    sizeof(struct xfrm_userspi_info), XFRMA_MARK, &dd, &dl) == 1 &&
	    dl == sizeof(struct xfrm_mark) &&
	    ((const struct xfrm_mark *)dd)->v == (0x100 & 0xff) &&
	    ((const struct xfrm_mark *)dd)->m == 0xff,
	    "getspi carries masked XFRMA_MARK v/m");
	CHECK(n && offload_rta_get((const char *)n, n->nlmsg_len,
	    sizeof(struct xfrm_userspi_info), XFRMA_IF_ID, &dd, &dl) == 1 &&
	    dl == 4 && *(const unsigned int *)dd == 7,
	    "getspi carries XFRMA_IF_ID");

	/* DELPOLICY by index (spmd's delete path — kernel byid matches mark) */
	setup();
	memset(&rc, 0, sizeof(rc));
	rc.so = rcm.so; rc.seq = 0x4010001; rc.slid = 42;
	rc.dir = RCT_DIR_OUTBOUND; rc.mark = 0x100; rc.mark_mask = 0xff;
	rc.if_id = 7;
	CHECK(rcpfk_send_spddelete2(&rc) == 0, "spddelete2: %s", rc.estr);
	n = kget();
	CHECK(n && n->nlmsg_type == XFRM_MSG_DELPOLICY,
	    "DELPOLICY(by-index) on req socket");
	CHECK(n && offload_rta_get((const char *)n, n->nlmsg_len,
	    sizeof(struct xfrm_userpolicy_id), XFRMA_MARK, &dd, &dl) == 1 &&
	    dl == sizeof(struct xfrm_mark) &&
	    ((const struct xfrm_mark *)dd)->v == (0x100 & 0xff) &&
	    ((const struct xfrm_mark *)dd)->m == 0xff,
	    "spddelete2 carries masked XFRMA_MARK v/m");
	CHECK(n && offload_rta_get((const char *)n, n->nlmsg_len,
	    sizeof(struct xfrm_userpolicy_id), XFRMA_IF_ID, &dd, &dl) == 1 &&
	    dl == 4 && *(const unsigned int *)dd == 7,
	    "spddelete2 carries XFRMA_IF_ID");

	/* GETPOLICY by index (spmd's fetch path) */
	setup();
	memset(&rc, 0, sizeof(rc));
	rc.so = rcm.so; rc.seq = 0x4010002; rc.slid = 42;
	rc.dir = RCT_DIR_OUTBOUND; rc.mark = 0x100; rc.mark_mask = 0xff;
	rc.if_id = 7;
	CHECK(rcpfk_send_spdget(&rc) == 0, "spdget: %s", rc.estr);
	n = kget();
	CHECK(n && n->nlmsg_type == XFRM_MSG_GETPOLICY,
	    "GETPOLICY(by-index) on req socket");
	CHECK(n && offload_rta_get((const char *)n, n->nlmsg_len,
	    sizeof(struct xfrm_userpolicy_id), XFRMA_MARK, &dd, &dl) == 1 &&
	    dl == sizeof(struct xfrm_mark) &&
	    ((const struct xfrm_mark *)dd)->v == (0x100 & 0xff) &&
	    ((const struct xfrm_mark *)dd)->m == 0xff,
	    "spdget carries masked XFRMA_MARK v/m");
	CHECK(n && offload_rta_get((const char *)n, n->nlmsg_len,
	    sizeof(struct xfrm_userpolicy_id), XFRMA_IF_ID, &dd, &dl) == 1 &&
	    dl == 4 && *(const unsigned int *)dd == 7,
	    "spdget carries XFRMA_IF_ID");

	/* DELSA + GETSA (state key); mark is part of the state lookup key */
	setup();
	fill_sa_rc(&rc, &s, &d, 0x4010010, 0x1001);
	rc.so = rcm.so; rc.mark = 0x100; rc.mark_mask = 0xff; rc.if_id = 7;
	CHECK(rcpfk_send_delete(&rc) == 0, "delsa: %s", rc.estr);
	n = kget();
	CHECK(n && n->nlmsg_type == XFRM_MSG_DELSA, "DELSA on req socket");
	CHECK(n && offload_rta_get((const char *)n, n->nlmsg_len,
	    sizeof(struct xfrm_usersa_id), XFRMA_MARK, &dd, &dl) == 1 &&
	    dl == sizeof(struct xfrm_mark) &&
	    ((const struct xfrm_mark *)dd)->v == (0x100 & 0xff) &&
	    ((const struct xfrm_mark *)dd)->m == 0xff,
	    "delsa carries masked XFRMA_MARK v/m");
	CHECK(n && offload_rta_get((const char *)n, n->nlmsg_len,
	    sizeof(struct xfrm_usersa_id), XFRMA_IF_ID, &dd, &dl) == 1 &&
	    dl == 4 && *(const unsigned int *)dd == 7,
	    "delsa carries XFRMA_IF_ID");
	setup();
	fill_sa_rc(&rc, &s, &d, 0x4010011, 0x1001);
	rc.so = rcm.so; rc.mark = 0x100; rc.mark_mask = 0xff; rc.if_id = 7;
	CHECK(rcpfk_send_get(&rc) == 0, "getsa: %s", rc.estr);
	n = kget();
	CHECK(n && n->nlmsg_type == XFRM_MSG_GETSA, "GETSA on req socket");
	CHECK(n && offload_rta_get((const char *)n, n->nlmsg_len,
	    sizeof(struct xfrm_usersa_id), XFRMA_MARK, &dd, &dl) == 1 &&
	    dl == sizeof(struct xfrm_mark) &&
	    ((const struct xfrm_mark *)dd)->v == (0x100 & 0xff) &&
	    ((const struct xfrm_mark *)dd)->m == 0xff,
	    "getsa carries masked XFRMA_MARK v/m");
	CHECK(n && offload_rta_get((const char *)n, n->nlmsg_len,
	    sizeof(struct xfrm_usersa_id), XFRMA_IF_ID, &dd, &dl) == 1 &&
	    dl == 4 && *(const unsigned int *)dd == 7,
	    "getsa carries XFRMA_IF_ID");
}

/*
 * Two ops in flight (seq-keyed op table): the reply to the FIRST arrives
 * after the second was sent.  Both callbacks must fire, in reply order,
 * and nothing may be dropped as stale.  With one pending slot the first
 * op's ALLOCSPI body was dropped and cb_getspi never ran.
 */
static void
test_overlapping_ops_both_complete(void)
{
	struct rcpfk_msg rc;
	struct sockaddr_in s, d;
	char buf[512];
	int r;

	setup();
	fill_sa_rc(&rc, &s, &d, 0x4000800, 0);
	CHECK(rcpfk_send_getspi(&rc) == 0, "getspi: %s", rc.estr);
	(void)kget();
	fill_sa_rc(&rc, &s, &d, 0x4000801, 0x5005);
	rc.enctype = RCT_ALG_AES_GCM; rc.enckeylen = 20;
	rc.enckey = (caddr_t)"0123456789abcdefghij";
	CHECK(rcpfk_send_update(&rc) == 0, "update: %s", rc.estr);
	(void)kget();
	CHECK(xfrm_nops == 2, "two ops outstanding (%d)", xfrm_nops);
	/* second op's ACK first, then the first op's ALLOCSPI reply */
	kput(k_req, buf, mk_err(buf, 0x4000801, PORTID, 0, XFRM_MSG_UPDSA));
	kput(k_req, buf, mk_sa(buf, XFRM_MSG_NEWSA, 0x4000800, PORTID,
	    0x6006, 0));
	memset(&rc, 0, sizeof(rc));
	rc.so = rcm.so;
	r = rcpfk_handler(&rc);
	CHECK(r == 0, "handler: %s", rc.estr);
	CHECK(n_upd == 1, "second op (UPDSA) callback fired (%d)", n_upd);
	CHECK(n_getspi == 1, "first op (ALLOCSPI) callback fired (%d)",
	    n_getspi);
	CHECK(n_getspi == 1 && ntohl(last.spi) == 0x6006 &&
	    last.seq == 0x4000800, "getspi got its own reply (spi %x seq %x)",
	    ntohl(last.spi), last.seq);
	CHECK(xfrm_stat_stale_reply == 0 && xfrm_stat_late_error == 0,
	    "nothing dropped (stale %lu late %lu)", xfrm_stat_stale_reply,
	    xfrm_stat_late_error);
	CHECK(xfrm_nops == 0, "op table empty (%d)", xfrm_nops);
}

/*
 * Outside WAITREPLY, the failure of a non-newest op is returned with ITS
 * seq, so the caller can attribute it; the newer op stays outstanding and
 * still completes.
 */
static void
test_overlapping_error_attributed(void)
{
	struct rcpfk_msg rc;
	struct sockaddr_in s, d;
	char buf[256];
	int r;

	setup();
	fill_sa_rc(&rc, &s, &d, 0x4000900, 0x7007);
	rc.enctype = RCT_ALG_AES_GCM; rc.enckeylen = 20;
	rc.enckey = (caddr_t)"0123456789abcdefghij";
	CHECK(rcpfk_send_add(&rc) == 0, "add: %s", rc.estr);
	(void)kget();
	fill_sa_rc(&rc, &s, &d, 0x4000901, 0x7008);
	rc.enctype = RCT_ALG_AES_GCM; rc.enckeylen = 20;
	rc.enckey = (caddr_t)"0123456789abcdefghij";
	CHECK(rcpfk_send_add(&rc) == 0, "add 2: %s", rc.estr);
	(void)kget();
	kput(k_req, buf, mk_err(buf, 0x4000900, PORTID, EINVAL,
	    XFRM_MSG_NEWSA));
	memset(&rc, 0, sizeof(rc));
	rc.so = rcm.so;
	r = rcpfk_handler(&rc);
	CHECK(r == -1 && rc.eno == EINVAL, "first op's EINVAL returned (r=%d "
	    "eno=%d)", r, rc.eno);
	CHECK(xfrm_nops == 1 && op_find(0x4000901) != NULL &&
	    op_find(0x4000900) == NULL, "only the failed op released");
	CHECK(n_add == 0, "no success callback for the failed op");
	kput(k_req, buf, mk_err(buf, 0x4000901, PORTID, 0, XFRM_MSG_NEWSA));
	memset(&rc, 0, sizeof(rc));
	rc.so = rcm.so;
	r = rcpfk_handler(&rc);
	CHECK(r == 0 && n_add == 1 && last.seq == 0x4000901,
	    "second op still completes (r=%d n_add=%d seq %x)", r, n_add,
	    last.seq);
	CHECK(xfrm_nops == 0, "op table empty (%d)", xfrm_nops);
}

/*
 * A kernel DELSA/DELPOLICY event (expiry, other daemon: pid 0 / foreign)
 * must not release an outstanding op of ours: that op's reply would then
 * be dropped as stale and its callback never run.
 */
static void
test_foreign_delete_event_keeps_op(void)
{
	struct rcpfk_msg rc;
	struct sockaddr_in s, d;
	char buf[512];
	int r;

	setup();
	fill_sa_rc(&rc, &s, &d, 0x4000a00, 0x8008);
	rc.enctype = RCT_ALG_AES_GCM; rc.enckeylen = 20;
	rc.enckey = (caddr_t)"0123456789abcdefghij";
	CHECK(rcpfk_send_add(&rc) == 0, "add: %s", rc.estr);
	(void)kget();
	kput(k_ntf, buf, mk_sa(buf, XFRM_MSG_DELSA, 0, 0, 0x9999, 0));
	kput(k_ntf, buf, mk_policy(buf, XFRM_MSG_DELPOLICY, 0, 0,
	    "203.0.113.1", "203.0.113.0", 0));
	memset(&rc, 0, sizeof(rc));
	rc.so = rcm.so;
	r = rcpfk_handler(&rc);
	CHECK(r == 0, "events: %s", rc.estr);
	CHECK(n_del == 1 && n_spddel == 1, "both events delivered (%d/%d)",
	    n_del, n_spddel);
	CHECK(op_find(0x4000a00) != NULL, "outstanding NEWSA survives the "
	    "events");
	kput(k_req, buf, mk_err(buf, 0x4000a00, PORTID, 0, XFRM_MSG_NEWSA));
	memset(&rc, 0, sizeof(rc));
	rc.so = rcm.so;
	r = rcpfk_handler(&rc);
	CHECK(r == 0 && n_add == 1, "its ACK still fires cb_add (r=%d n=%d)",
	    r, n_add);
	CHECK(xfrm_stat_stale_reply == 0, "ACK not dropped as stale (%lu)",
	    xfrm_stat_stale_reply);
}

/* The op table is bounded: a submit that finds it full fails EAGAIN,
 * sends nothing, and never evicts an outstanding op. */
static void
test_op_table_full(void)
{
	struct rcpfk_msg rc;
	int i;

	setup();
	for (i = 0; i < XFRM_OPS_MAX; i++) {
		memset(&rc, 0, sizeof(rc));
		rc.so = rcm.so;
		rc.seq = 0xb00 + (uint32_t)i;
		rc.slid = (uint32_t)i + 1;
		CHECK(rcpfk_send_spdget(&rc) == 0, "spdget %d: %s", i, rc.estr);
		CHECK(kget() != NULL, "spdget %d sent", i);
	}
	memset(&rc, 0, sizeof(rc));
	rc.so = rcm.so;
	rc.seq = 0xbff;
	rc.slid = 99;
	CHECK(rcpfk_send_spdget(&rc) == -1 && rc.eno == EAGAIN,
	    "op beyond the table fails EAGAIN (eno %d)", rc.eno);
	CHECK(kget() == NULL, "nothing sent for the refused op");
	CHECK(xfrm_stat_ops_full == 1, "refusal counted (%lu)",
	    xfrm_stat_ops_full);
	CHECK(xfrm_nops == XFRM_OPS_MAX && op_find(0xb00) != NULL &&
	    op_find(0xbff) == NULL, "no outstanding op evicted");
}

/*
 * A request socket that overflows on every read during the resync dump
 * must not restart forever: give up past XFRM_RESYNC_MAX_RETRY with EAGAIN,
 * and leave the resync armed for a later round, which then succeeds.
 */
static void
test_resync_retry_cap(void)
{
	struct rcpfk_msg rc;
	pthread_t th;
	int r;

	setup();
	kthr_stop = 0;
	kthr_spd = kthr_sa = 0;
	if (pthread_create(&th, NULL, kthr, NULL) != 0)
		exit(99);
	xfrm_need_resync = 1;
	xfrm_test_enobufs_fd = xfrm_req_fd;
	/* one overflow ends the handler's read loop, MAX+1 more overflow
	 * every resync pass */
	xfrm_test_enobufs_more = XFRM_RESYNC_MAX_RETRY + 1;
	memset(&rc, 0, sizeof(rc));
	rc.so = rcm.so;
	r = rcpfk_handler(&rc);
	CHECK(r == -1 && rc.eno == EAGAIN, "resync gives up past the cap "
	    "(r=%d eno=%d %s)", r, rc.eno, rc.estr);
	CHECK(xfrm_stat_resync == XFRM_RESYNC_MAX_RETRY + 1,
	    "exactly MAX+1 resync passes (%lu)", xfrm_stat_resync);
	CHECK(n_resync == 0, "cb_resync not run for an incomplete resync");
	CHECK(xfrm_need_resync == 1, "resync stays armed after giving up");
	CHECK(xfrm_test_enobufs_fd == -1, "all injected overflows consumed");
	/* storm over: drain stale dump replies, next round completes */
	usleep(120000);
	while (xfrm_read_one(xfrm_req_fd, &rc, MSG_DONTWAIT, 1) == 1)
		;
	memset(&rc, 0, sizeof(rc));
	rc.so = rcm.so;
	r = rcpfk_handler(&rc);
	CHECK(r == 0, "later round resyncs: %s", rc.estr);
	CHECK(n_resync == 1 && xfrm_need_resync == 0, "resync completed "
	    "(n_resync %d armed %d)", n_resync, xfrm_need_resync);
	kthr_stop = 1;
	pthread_join(th, NULL);
}

/* cb_resync failing must surface as a handler error, not a silent 0 */
static int cb_resync_fail(struct rcpfk_msg *r) { n_resync++; (void)r; return -1; }
static void
test_resync_cb_failure_reported(void)
{
	struct rcpfk_msg rc;
	pthread_t th;
	int r;

	setup();
	tcb.cb_resync = cb_resync_fail;
	kthr_stop = 0;
	if (pthread_create(&th, NULL, kthr, NULL) != 0)
		exit(99);
	xfrm_need_resync = 1;
	memset(&rc, 0, sizeof(rc));
	rc.so = rcm.so;
	r = rcpfk_handler(&rc);
	CHECK(r == -1 && n_resync == 1, "failed cb_resync reported (r=%d "
	    "n=%d)", r, n_resync);
	CHECK(strstr(rc.estr, "resync callback failed") != NULL,
	    "estr names it (%s)", rc.estr);
	kthr_stop = 1;
	pthread_join(th, NULL);
	tcb.cb_resync = cb_resync;
}

/* Policy send path: a mixed specified pair is refused before anything is
 * sent or an op is recorded; a wildcard v6 side coerces to the v4 peer on
 * the wire (hermetic: decodes the request bytes, no iproute2 text). */
static void
test_policy_path_mixed_family(void)
{
	struct rcpfk_msg rc;
	struct sockaddr_in s4;
	struct sockaddr_in6 d6;
	struct nlmsghdr *n;
	struct xfrm_userpolicy_info *xp;

	setup();
	memset(&s4, 0, sizeof(s4));
	s4.sin_family = AF_INET;
	inet_pton(AF_INET, "192.0.2.1", &s4.sin_addr);
	memset(&d6, 0, sizeof(d6));
	d6.sin6_family = AF_INET6;
	inet_pton(AF_INET6, "2001:db8::1", &d6.sin6_addr);
	memset(&rc, 0, sizeof(rc));
	rc.so = rcm.so;
	rc.seq = 0xc00;
	rc.sp_src = (void *)&s4;
	rc.sp_dst = (void *)&d6;
	rc.pref_src = 32;
	rc.pref_dst = 128;
	rc.pltype = RCT_ACT_DISCARD;
	rc.dir = RCT_DIR_OUTBOUND;
	CHECK(rcpfk_send_spdadd(&rc) == -1 && rc.eno == EINVAL,
	    "mixed spdadd refused EINVAL (eno %d)", rc.eno);
	CHECK(kget() == NULL, "nothing sent for the mixed spdadd");
	CHECK(xfrm_nops == 0, "no op recorded (%d)", xfrm_nops);
	rc.eno = 0;
	CHECK(rcpfk_send_spddelete(&rc) == -1 && rc.eno == EINVAL,
	    "mixed spddelete refused EINVAL (eno %d)", rc.eno);
	CHECK(kget() == NULL, "nothing sent for the mixed spddelete");

	/* v6 wildcard src + v4 dst: AF_INET selector with the v4 address */
	memset(&d6, 0, sizeof(d6));
	d6.sin6_family = AF_INET6;
	memset(&rc, 0, sizeof(rc));
	rc.so = rcm.so;
	rc.seq = 0xc01;
	rc.sp_src = (void *)&d6;
	rc.sp_dst = (void *)&s4;
	rc.pref_src = 0;
	rc.pref_dst = 32;
	rc.pltype = RCT_ACT_DISCARD;
	rc.dir = RCT_DIR_OUTBOUND;
	CHECK(rcpfk_send_spdadd(&rc) == 0, "spdadd: %s", rc.estr);
	n = kget();
	CHECK(n != NULL, "spdadd sent");
	if (n) {
		xp = NLMSG_DATA(n);
		CHECK(xp->sel.family == AF_INET, "wire family AF_INET (%u)",
		    xp->sel.family);
		CHECK(xp->sel.saddr.a4 == 0 && xp->sel.daddr.a4 ==
		    s4.sin_addr.s_addr, "wire addrs any -> 192.0.2.1");
	}
}

int
main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	if (rbuf_init(8, 80, 4, 160, 4))
		return 99;
	plog_setmode(RCT_LOGMODE_NORMAL, NULL, "xfrmnltest", 1, 0);
	test_request_goes_to_req_socket();
	test_idempotence();
	test_ebusy_retry();
	test_interleaved_waitreply();
	test_waitreply_error();
	test_late_error_not_lost();
	test_overlapping_ops_both_complete();
	test_overlapping_error_attributed();
	test_foreign_delete_event_keeps_op();
	test_op_table_full();
	test_misaligned_batch();
	test_migrate_port_only_without_migrate();
	test_enobufs_resync();
	test_resync_retry_cap();
	test_resync_cb_failure_reported();
	test_mapping_migrate_fresh();
	test_short_messages();
	test_satype_proto_mapping();
	test_nl_walk();
	test_nl_recv();
	test_trunc_resync();
	test_sync_enobufs();
	test_fill_selector();
	test_policy_path_mixed_family();
	test_offload_attrs();
	test_mark_emit_live_paths();
	printf("%s: %d failure(s)\n", fails ? "FAIL" : "PASS", fails);
	return fails ? 1 : 0;
}
