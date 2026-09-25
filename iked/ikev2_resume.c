/* IKEv2 session resume across iked restart: dump ESTABLISHED SAs,
 * leave kernel ESP in place, restore cookies/keys/message IDs. */

#include <config.h>

#include <sys/types.h>
#include <stddef.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "gcmalloc.h"
#include "racoon.h"
#include "isakmp.h"
#include "ikev2.h"
#include "isakmp_impl.h"
#include "ikev2_impl.h"
#include "ike_conf.h"
#include "ike_pfkey.h"
#include "rc_net.h"
#include "debug.h"
#include "ikev2_resume_rec.h"

/*
 * Dump expire_at as wall-clock unix. sched.xtime under FIXY2038PROBLEM
 * is seconds since sched_init(), not time(3). Mixing them made load
 * clamp remaining to 1s (bounce 2026-09-08 21:59).
 */
#define RESUME_UNIX_FLOOR	1000000000u	/* 2001-09-09 */

#ifndef RESUME_DIR
#define RESUME_DIR		"/var/lib/racoon2/resume"
#endif
#define RESUME_DIR_LEGACY	"/var/run/racoon2/resume"

/*
 * Runtime override of the resume directory (RACOON2_RESUME_DIR), mirroring the
 * RACOON2_ADMIN_SOCK pattern: lets an isolated test harness steer its resume
 * dumps into a private dir so N test ikeds never read/write production's
 * /var/lib/racoon2/resume (a stale shared dump made a test responder skip a
 * fresh child with "pending ADDKE followup; skipped, will rekey").  When the
 * override is set, the shared legacy dir is likewise not touched.
 */
static int
r2_resume_override(void)
{
	const char *e = getenv("RACOON2_RESUME_DIR");
	return e && *e;
}
static const char *
r2_resume_dir(void)
{
	const char *e = getenv("RACOON2_RESUME_DIR");
	return (e && *e) ? e : RESUME_DIR;
}
static const char *
r2_resume_dir_legacy(void)
{
	const char *e = getenv("RACOON2_RESUME_DIR");
	return (e && *e) ? e : RESUME_DIR_LEGACY;
}

static time_t
resume_remain_from_dump(uint32_t expire_at, time_t now, time_t fallback)
{
	time_t remaining;

	/* v1 dumps stored FIXY xtime (~uptime+lifetime), not unix. */
	if (expire_at < RESUME_UNIX_FLOOR)
		return fallback;
	remaining = (time_t)expire_at - now;
	if (remaining < 1)
		remaining = 1;
	return remaining;
}

static uint32_t
resume_wall_expire(struct sched *sc, time_t fallback)
{
	time_t remaining;

	if (!sc || sc->dead)
		return (uint32_t)(time(NULL) + fallback);
	remaining = sched_remaining(sc);
	if (remaining < 1)
		remaining = 1;
	return (uint32_t)(time(NULL) + remaining);
}

static int
resume_dump_predates_boot(const char *path)
{
	struct stat st;
	time_t boot_time, now, up;
	FILE *f;
	double dup;

	if (stat(path, &st) < 0)
		return 0;
#ifdef CLOCK_BOOTTIME
	{
		struct timespec ts_up, ts_now;

		if (clock_gettime(CLOCK_BOOTTIME, &ts_up) == 0 &&
		    clock_gettime(CLOCK_REALTIME, &ts_now) == 0) {
			boot_time = ts_now.tv_sec - ts_up.tv_sec;
			return st.st_mtime < boot_time;
		}
	}
#endif
	f = fopen("/proc/uptime", "r");
	if (!f)
		return 0;
	if (fscanf(f, "%lf", &dup) != 1) {
		fclose(f);
		return 0;
	}
	fclose(f);
	now = time(NULL);
	up = (time_t)dup;
	boot_time = now - up;
	return st.st_mtime < boot_time;
}

static int
resume_copy_file(const char *from, const char *to)
{
	char buf[2048];
	int infd, outfd;
	ssize_t n, w, off;

	infd = open(from, O_RDONLY);
	if (infd < 0)
		return -1;
	outfd = open(to, O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (outfd < 0) {
		close(infd);
		return -1;
	}
	while ((n = read(infd, buf, sizeof(buf))) > 0) {
		off = 0;
		while (off < n) {
			w = write(outfd, buf + off, (size_t)(n - off));
			if (w < 0) {
				close(infd);
				close(outfd);
				unlink(to);
				return -1;
			}
			off += w;
		}
	}
	if (n < 0 || fsync(outfd) < 0) {
		close(infd);
		close(outfd);
		unlink(to);
		return -1;
	}
	close(infd);
	close(outfd);
	return 0;
}

static void
resume_migrate_legacy(void)
{
	DIR *d;
	struct dirent *de;
	char from[320], to[320];

	/* An explicit RACOON2_RESUME_DIR means a private/isolated set: never
	 * migrate from (or mkdir into) the shared production dirs. */
	if (r2_resume_override())
		return;
	(void)mkdir("/var/lib/racoon2", 0700);
	if (mkdir(r2_resume_dir(), 0700) < 0 && errno != EEXIST)
		return;
	d = opendir(r2_resume_dir_legacy());
	if (!d)
		return;
	while ((de = readdir(d)) != NULL) {
		if (de->d_name[0] == '.')
			continue;
		snprintf(from, sizeof(from), "%s/%s", r2_resume_dir_legacy(),
		    de->d_name);
		snprintf(to, sizeof(to), "%s/%s", r2_resume_dir(), de->d_name);
		if (rename(from, to) == 0)
			continue;
		if (errno == EXDEV && resume_copy_file(from, to) == 0)
			unlink(from);
	}
	closedir(d);
}

static void
resume_filename(char *buf, size_t buflen, const uint8_t i_ck[8],
    const uint8_t r_ck[8])
{
	r2rs_filename_in(buf, buflen, r2_resume_dir(), i_ck, r_ck);
}

static struct prop_pair *
spi_prop(int proto, uint32_t spi_host)
{
	struct prop_pair *p;
	struct isakmp_pl_p *prop;
	uint32_t nspi;

	p = racoon_calloc(1, sizeof(*p));
	prop = racoon_calloc(1, sizeof(*prop) + sizeof(uint32_t));
	if (!p || !prop) {
		if (p)
			racoon_free(p);
		if (prop)
			racoon_free(prop);
		return NULL;
	}
	prop->p_no = 1;
	prop->proto_id = (uint8_t)proto;
	prop->spi_size = sizeof(uint32_t);
	/* canonical placeholder length, same as ikev2_ipsec_conf_to_proplist:
	 * header + SPI; transforms are linked via tnext and the packer
	 * rewrites h.len.  Without this, a rekey of a resume-restored child
	 * clones a proposal with h.len=0 and ikev2_child_getspi_response's
	 * assert(1723) ABRTs the daemon on every restore. */
	put_uint16(&prop->h.len, sizeof(struct isakmp_pl_p) + sizeof(uint32_t));
	nspi = htonl(spi_host);
	memcpy(prop + 1, &nspi, sizeof(nspi));
	p->prop = prop;
	return p;
}

static int
prop_add_trns(struct prop_pair *p, uint8_t type, uint16_t id, uint16_t keylen)
{
	struct prop_pair *t, *tail;
	struct ikev2transform *tr;
	size_t extra = keylen ? 4 : 0;

	if (!p)
		return -1;
	t = racoon_calloc(1, sizeof(*t));
	tr = racoon_calloc(1, sizeof(*tr) + extra);
	if (!t || !tr) {
		if (t)
			racoon_free(t);
		if (tr)
			racoon_free(tr);
		return -1;
	}
	tr->more = IKEV2TRANSFORM_LAST;
	put_uint16(&tr->transform_length, (uint32_t)(sizeof(*tr) + extra));
	tr->transform_type = type;
	put_uint16(&tr->transform_id, id);
	if (keylen) {
		uint8_t *a = (uint8_t *)(tr + 1);
		put_uint16(a, 0x8000 | 14);
		put_uint16(a + 2, keylen);
	}
	t->trns = (struct isakmp_pl_t *)tr;
	if (!p->tnext) {
		p->tnext = t;
		return 0;
	}
	tail = p->tnext;
	while (tail->tnext)
		tail = tail->tnext;
	if (tail->trns)
		((struct ikev2transform *)tail->trns)->more = IKEV2TRANSFORM_MORE;
	tail->tnext = t;
	return 0;
}

static void
suite_from_prop(struct prop_pair *p, struct r2rs_child *c)
{
	struct prop_pair *t;

	c->encr_id = 0;
	c->integr_id = 0;
	c->encr_klen = 0;
	c->esn = 0;
	if (!p)
		return;
	for (t = p->tnext; t; t = t->tnext) {
		struct ikev2transform *tr;
		uint16_t tlen;

		if (!t->trns)
			continue;
		tr = (struct ikev2transform *)t->trns;
		tlen = get_uint16(&tr->transform_length);
		switch (tr->transform_type) {
		case IKEV2TRANSFORM_TYPE_ENCR:
			c->encr_id = get_uint16(&tr->transform_id);
			if (tlen >= sizeof(*tr) + 4) {
				uint16_t at = get_uint16(tr + 1);
				if ((at & 0x7fff) == 14)
					c->encr_klen = get_uint16(
					    (uint8_t *)(tr + 1) + 2);
			}
			break;
		case IKEV2TRANSFORM_TYPE_INTEGR:
			c->integr_id = get_uint16(&tr->transform_id);
			break;
		case IKEV2TRANSFORM_TYPE_ESN:
			c->esn = (uint8_t)get_uint16(&tr->transform_id);
			break;
		default:
			break;
		}
	}
}

static uint32_t
prop_spi_host(struct prop_pair *proposal)
{
	struct isakmp_pl_p *prop;

	if (!proposal || !proposal->prop)
		return 0;
	prop = proposal->prop;
	if (prop->spi_size < 4)
		return 0;
	return get_uint32(prop + 1);
}

void
ikev2_resume_forget(struct ikev2_sa *sa)
{
	char path[192];

	if (!sa)
		return;
	r2rs_filename_in(path, sizeof(path), r2_resume_dir(), sa->index.i_ck,
	    sa->index.r_ck);
	unlink(path);
	r2rs_filename_in(path, sizeof(path), r2_resume_dir_legacy(), sa->index.i_ck,
	    sa->index.r_ck);
	unlink(path);
}

void
ikev2_resume_save(struct ikev2_sa *sa)
{
	struct r2rs_sa rec;
	struct ikev2_child_sa *ch;
	char path[192], tmp[200];
	int fd, n;
	size_t wr;
	uint16_t lfam, lport, rfam, rport;

	if (!sa || sa->state != IKEV2_STATE_ESTABLISHED)
		return;
	if (!sa->sk_d || !sa->sk_e_i || !sa->sk_e_r || !sa->negotiated_sa)
		return;

	memset(&rec, 0, sizeof(rec));
	rec.magic = R2RS_MAGIC;
	rec.version = R2RS_VERSION;
	memcpy(rec.i_ck, sa->index.i_ck, 8);
	memcpy(rec.r_ck, sa->index.r_ck, 8);
	rec.is_initiator = sa->is_initiator ? 1 : 0;
	rec.mobike = sa->mobike_supported ? 1 : 0;
	rec.frag = sa->frag_supported ? 1 : 0;
	rec.behind_nat = sa->behind_nat ? 1 : 0;
	rec.peer_behind_nat = sa->peer_behind_nat ? 1 : 0;
	rec.send_message_id = sa->send_message_id;
	rec.recv_message_id = sa->recv_message_id;
	rec.ike_expire_at = resume_wall_expire(sa->expire_timer, 86400);
	rec.encr = sa->negotiated_sa->encr;
	rec.encrklen = sa->negotiated_sa->encrklen;
	rec.prf = sa->negotiated_sa->prf;
	rec.integr = sa->negotiated_sa->integr;
	rec.dh_id = sa->negotiated_sa->dhdef ?
	    (int32_t)sa->negotiated_sa->dhdef->transform_id : 0;
	r2rs_sa_to_wire(sa->local, &lfam, &lport, rec.local_addr);
	rec.local_family = lfam;
	rec.local_port = lport;
	r2rs_sa_to_wire(sa->remote, &rfam, &rport, rec.remote_addr);
	rec.remote_family = rfam;
	rec.remote_port = rport;
	if (sa->rmconf && sa->rmconf->rm_index)
		snprintf(rec.rm_index, sizeof(rec.rm_index), "%s",
		    rc_vmem2str(sa->rmconf->rm_index));
	r2rs_key_from_vchar(&rec.sk_d, sa->sk_d);
	r2rs_key_from_vchar(&rec.sk_ai, sa->sk_a_i);
	r2rs_key_from_vchar(&rec.sk_ar, sa->sk_a_r);
	r2rs_key_from_vchar(&rec.sk_ei, sa->sk_e_i);
	r2rs_key_from_vchar(&rec.sk_er, sa->sk_e_r);
	r2rs_key_from_vchar(&rec.sk_pi, sa->sk_p_i);
	r2rs_key_from_vchar(&rec.sk_pr, sa->sk_p_r);
	r2rs_key_from_vchar(&rec.n_i, sa->n_i);
	r2rs_key_from_vchar(&rec.n_r, sa->n_r);
	r2rs_key_from_vchar(&rec.id_i, sa->id_i);
	r2rs_key_from_vchar(&rec.id_r, sa->id_r);

	n = 0;
	for (ch = IKEV2_CHILD_LIST_FIRST(&sa->children);
	     !IKEV2_CHILD_LIST_END(ch) && n < R2RS_MAXCHILD;
	     ch = IKEV2_CHILD_LIST_NEXT(ch)) {
		struct rcf_address *a;
		uint32_t in_spi = 0, out_spi = 0;

		if (ch->state != IKEV2_CHILD_STATE_MATURE)
			continue;
		if (ch->my_proposal && ch->my_proposal[1])
			in_spi = prop_spi_host(ch->my_proposal[1]);
		if (ch->peer_proposal)
			out_spi = prop_spi_host(ch->peer_proposal);
		if (!in_spi || !out_spi)
			continue;
		rec.child[n].in_spi = in_spi;
		rec.child[n].out_spi = out_spi;
		rec.child[n].satype = IKEV2PROPOSAL_ESP;
		rec.child[n].expire_at = resume_wall_expire(ch->timer, 3600);
		/* RFC 9370 ADDKE: persist the pending followup state so a
		 * restart mid-PQC-rekey is recognizable on restore.  The
		 * keymat for such a child is incomplete (SK(1) pending), so
		 * restore must skip it; recording the link/method keeps the
		 * dump truthful for debugging. */
		rec.child[n].addke_pending = (ch->addke_pending ? 1 : 0);
		rec.child[n].addke_method = (uint16_t)ch->addke_method;
		if (ch->addke_pending && ch->addke_link &&
		    ch->addke_link->l <= sizeof(rec.child[n].addke_link)) {
			rec.child[n].addke_link_len =
			    (uint8_t)ch->addke_link->l;
			memcpy(rec.child[n].addke_link,
			       ch->addke_link->v, ch->addke_link->l);
		}
		if (ch->selector && ch->selector->sl_index)
			snprintf(rec.child[n].sl_index,
			    sizeof(rec.child[n].sl_index), "%s",
			    rc_vmem2str(ch->selector->sl_index));
		a = LIST_FIRST(&ch->lease_list);
		if (a) {
			rec.child[n].lease_af = (uint8_t)a->af;
			memcpy(rec.child[n].lease_addr, a->address, 16);
		}
		if (ch->my_proposal && ch->my_proposal[1])
			suite_from_prop(ch->my_proposal[1], &rec.child[n]);
		n++;
	}
	rec.nchild = (uint32_t)n;

	/* v4: persist the last-armed response (whole-packet form only;
	 * frags are variable-length, skip them) so a restart replays a
	 * retransmitted request instead of dropping it as unordered. */
	rec.resp_msgid = sa->response_info.message_id;
	rec.resp_len = 0;
	if (sa->response_info.packet && !sa->response_info.frags &&
	    sa->response_info.packet->l > 0 &&
	    sa->response_info.packet->l <= R2RS_MAXRESP) {
		rec.resp_len = (uint16_t)sa->response_info.packet->l;
		memcpy(rec.resp_buf, sa->response_info.packet->v,
		    rec.resp_len);
	}

	(void)mkdir("/var/lib/racoon2", 0700);
	if (mkdir(r2_resume_dir(), 0700) < 0 && errno != EEXIST) {
		isakmp_log(sa, 0, 0, 0, PLOG_INTERR, PLOGLOC,
			   "resume: mkdir %s failed\n", r2_resume_dir());
		return;
	}
	resume_filename(path, sizeof(path), rec.i_ck, rec.r_ck);
	snprintf(tmp, sizeof(tmp), "%s.tmp", path);
	fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0) {
		isakmp_log(sa, 0, 0, 0, PLOG_INTERR, PLOGLOC,
			   "resume: open dump failed\n");
		return;
	}
	wr = write(fd, &rec, sizeof(rec));
	if (wr != sizeof(rec) || fsync(fd) < 0) {
		close(fd);
		unlink(tmp);
		isakmp_log(sa, 0, 0, 0, PLOG_INTERR, PLOGLOC,
			   "resume: write dump failed\n");
		return;
	}
	close(fd);
	if (rename(tmp, path) < 0) {
		unlink(tmp);
		isakmp_log(sa, 0, 0, 0, PLOG_INTERR, PLOGLOC,
			   "resume: rename dump failed\n");
		return;
	}
	isakmp_log(sa, 0, 0, 0, PLOG_INFO, PLOGLOC,
		   "resume: saved children=%u ike_remain=%ld\n", rec.nchild,
		   (long)(rec.ike_expire_at - (uint32_t)time(NULL)));
}

void
ikev2_resume_dump_all(void)
{
	struct ikev2_sa *sa;

	for (sa = IKEV2_SA_LIST_FIRST(&ikev2_sa_list); sa;
	     sa = IKEV2_SA_LIST_NEXT(sa))
		ikev2_resume_save(sa);
}

static int
restore_one(const char *path)
{
	struct r2rs_sa rec;
	struct ikev2_sa *sa = NULL;
	struct rcf_remote *conf = NULL;
	struct ikev2_isakmpsa *nsa = NULL;
	struct sockaddr *local = NULL, *remote = NULL;
	rc_vchar_t *rmidx = NULL;
	int fd, i, kernel_lost;
	time_t now = time(NULL);

	kernel_lost = resume_dump_predates_boot(path);
	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;
	{
		ssize_t nr = read(fd, &rec, sizeof(rec));
		close(fd);
		if (nr < 0)
			return -1;
		if (nr != (ssize_t)sizeof(rec)) {
			/* v3 dump: prefix-sized, zero the v4 tail */
			if (nr == (ssize_t)offsetof(struct r2rs_sa, resp_msgid))
				memset((char *)&rec + nr, 0,
				    sizeof(rec) - nr);
			else
				return -1;
		}
	}

	/* structural validation: magic/version, child count, key
	 * lengths (a corrupt len on disk would make
	 * r2rs_key_to_vchar read past its fixed array), child
	 * SPI/lease sanity. */
	if (r2rs_validate(&rec) != 0)
		return -1;

	/* validated above, but keep the bound local as a second
	 * line of defense against an unterminated rm_index. */
	rmidx = rc_vnew(rec.rm_index, strnlen(rec.rm_index, R2RS_MAXSTR));
	if (!rmidx || rcf_get_remotebyindex(rmidx, &conf) != 0) {
		plog(PLOG_INTERR, PLOGLOC, 0,
		    "resume: remote %s not in config\n", rec.rm_index);
		if (rmidx)
			rc_vfree(rmidx);
		return -1;
	}
	rc_vfree(rmidx);

	local = r2rs_wire_to_sa(rec.local_family, rec.local_port, rec.local_addr);
	remote = r2rs_wire_to_sa(rec.remote_family, rec.remote_port, rec.remote_addr);
	if (!local || !remote)
		goto fail;

	/* responder allocate (i_ck known), then pin r_ck from dump */
	sa = ikev2_allocate_sa((isakmp_cookie_t *)rec.i_ck, local, remote, conf);
	if (!sa)
		goto fail;
	conf = NULL;
	if (ikev2_half_open_sa > 0)
		--ikev2_half_open_sa;
	ikev2_sa_stop_timer(sa);
	sa->is_initiator = rec.is_initiator;
	sa->verified_info.is_initiator = rec.is_initiator;
	memcpy(sa->index.r_ck, rec.r_ck, 8);
	sa->send_message_id = rec.send_message_id;
	sa->recv_message_id = rec.recv_message_id;
	sa->mobike_supported = rec.mobike;
	sa->frag_supported = rec.frag;
	sa->behind_nat = rec.behind_nat;
	sa->peer_behind_nat = rec.peer_behind_nat;

	/*
	 * Re-pin the INIT binding-report digests.  The resume dump
	 * carries cookies and endpoints but not the NATD digests we
	 * sent in the INIT reply, so a restored SA would report 20
	 * zero bytes at the first RFC 4555 §3.8 NATD probe.  iOS
	 * compares our DESTINATION_IP digest against the value from
	 * the previous response and treats a change like a NAT
	 * re-bind - dropping the data plane while the UI still
	 * shows Connected (observed live: ESP died 16:25:15 at the
	 * +600s probe after a 16:22:48 resume-restored session).
	 * Digests are a pure function of SPIs + endpoints, all of
	 * which are restored above, so this reproduces the exact
	 * INIT values.
	 *
	 * Edge case: this reproduces the INIT digests only when the
	 * restored remote port still matches the port used at INIT.
	 * If the peer re-bound without an UPDATE_SA_ADDRESSES (RFC
	 * 4555 §3.8 requires one for address changes; a silent port
	 * drift is a peer violation), the re-pinned digests would
	 * differ from the INIT baseline and the next §3.8 compare
	 * would read as a binding change.  Acceptable; the correct
	 * signal path is the inbound peer-vs-previous-peer drift log.
	 */
	ikev2_sa_repin_natd(sa);

	nsa = racoon_calloc(1, sizeof(*nsa));
	if (!nsa)
		goto fail;
	nsa->encr = rec.encr;
	nsa->encrklen = rec.encrklen;
	nsa->prf = rec.prf;
	nsa->integr = rec.integr;
	if (rec.dh_id)
		nsa->dhdef = ikev2_dhinfo((unsigned int)rec.dh_id);
	if (ikev2_set_negotiated_sa(sa, nsa) != 0) {
		racoon_free(nsa);
		nsa = NULL;
		goto fail;
	}
	nsa = NULL;

	/* v4: rebuild the armed response so a retransmitted request is
	 * answered with the exact bytes we sent pre-restart. */
	if (rec.version >= 4 && rec.resp_len > 0 &&
	    rec.resp_len <= R2RS_MAXRESP) {
		sa->response_info.packet = rc_vnew(rec.resp_buf, rec.resp_len);
		if (sa->response_info.packet) {
			sa->response_info.message_id = rec.resp_msgid;
			sa->response_info.src = rcs_sadup(sa->local);
			sa->response_info.dest = rcs_sadup(sa->remote);
		}
	}

	sa->sk_d = r2rs_key_to_vchar(&rec.sk_d);
	sa->sk_a_i = r2rs_key_to_vchar(&rec.sk_ai);
	sa->sk_a_r = r2rs_key_to_vchar(&rec.sk_ar);
	sa->sk_e_i = r2rs_key_to_vchar(&rec.sk_ei);
	sa->sk_e_r = r2rs_key_to_vchar(&rec.sk_er);
	sa->sk_p_i = r2rs_key_to_vchar(&rec.sk_pi);
	sa->sk_p_r = r2rs_key_to_vchar(&rec.sk_pr);
	sa->n_i = r2rs_key_to_vchar(&rec.n_i);
	sa->n_r = r2rs_key_to_vchar(&rec.n_r);
	sa->id_i = r2rs_key_to_vchar(&rec.id_i);
	sa->id_r = r2rs_key_to_vchar(&rec.id_r);
	if (!sa->sk_d || !sa->sk_e_i || !sa->sk_e_r)
		goto fail;

	for (i = 0; i < (int)rec.nchild; i++) {
		struct ikev2_child_sa *ch;
		struct r2rs_child *c = &rec.child[i];
		time_t remain;
		struct rcf_addresspool *pool;
		struct rcf_address *addr;

		/*
		 * RFC 9370 ADDKE: a child whose keymat+install was
		 * deferred to the (unfinished) IKE_FOLLOWUP_KE cannot be
		 * restored — SK(1) is missing, so installing it would
		 * silently produce keys that diverge from the peer.
		 * The IKE_SA survives; the child rekeys fresh (RFC 9370
		 * optionality lets the peer offer ADDKE again, or plain).
		 */
		if (c->addke_pending) {
			isakmp_log(sa, 0, 0, 0, PLOG_PROTOWARN, PLOGLOC,
			    "resume: child %d pending ADDKE followup "
			    "(method %u); skipped, will rekey\n",
			    i, c->addke_method);
			continue;
		}

		ch = ikev2_create_child_sa(sa, TRUE);
		if (!ch)
			goto fail;
		ch->is_initiator = 0;
		ch->local = rcs_sadup(sa->local);
		ch->remote = rcs_sadup(sa->remote);
		if (!c->sl_index[0]) {
			plog(PLOG_INTERR, PLOGLOC, 0,
			    "resume: child %d missing selector\n", i);
			goto fail;
		}
		if (rcf_get_selector(c->sl_index, &ch->selector) != 0) {
			plog(PLOG_INTERR, PLOGLOC, 0,
			    "resume: selector %s missing\n", c->sl_index);
			goto fail;
		}
		ch->my_proposal = proplist_new();
		if (!ch->my_proposal)
			goto fail;
		ch->my_proposal[1] = spi_prop(IKEV2PROPOSAL_ESP, c->in_spi);
		ch->peer_proposal = spi_prop(IKEV2PROPOSAL_ESP, c->out_spi);
		if (!ch->my_proposal[1] || !ch->peer_proposal)
			goto fail;
		if (c->encr_id) {
			if (prop_add_trns(ch->my_proposal[1],
			    IKEV2TRANSFORM_TYPE_ENCR, c->encr_id,
			    c->encr_klen) != 0)
				goto fail;
			if (c->integr_id &&
			    prop_add_trns(ch->my_proposal[1],
			    IKEV2TRANSFORM_TYPE_INTEGR, c->integr_id, 0) != 0)
				goto fail;
			if (prop_add_trns(ch->my_proposal[1],
			    IKEV2TRANSFORM_TYPE_ESN, c->esn ? 1 : 0, 0) != 0)
				goto fail;
		}
		sadb_request_initialize(&ch->sadb_request,
		    debug_pfkey ? &sadb_debug_method :
		    &sadb_responder_request_method,
		    &ikev2_sadb_callback, sadb_new_seq(), ch);
		if (c->lease_af && sa->rmconf) {
			pool = ikev2_addresspool(sa->rmconf);
			if (pool) {
				addr = rc_addrpool_assign(pool, c->lease_af,
				    c->lease_addr);
				if (addr)
					LIST_INSERT_HEAD(&ch->lease_list,
					    addr, link_sa);
			}
		}
		ch->state = IKEV2_CHILD_STATE_MATURE;
		if (kernel_lost)
			remain = 1;
		else
			remain = resume_remain_from_dump(c->expire_at, now,
			    IKEV2_DEFAULT_IPSEC_LIFETIME_TIME);
		ikev2_child_arm_expire(ch, remain);
	}

	sa->child_created = (int)rec.nchild;
	sa->state = IKEV2_STATE_ESTABLISHED;
	{
		time_t remain = resume_remain_from_dump(rec.ike_expire_at, now,
		    ikev2_kmp_sa_lifetime_time(sa->rmconf));

		ikev2_sa_arm_lifetime(sa, (int)remain);
		isakmp_log(sa, 0, 0, 0, PLOG_INFO, PLOGLOC,
		    "resumed IKE_SA %s children=%u msgid %u/%u ike_remain=%ld%s\n",
		    rcs_sa2str(sa->remote), rec.nchild,
		    rec.send_message_id, rec.recv_message_id, (long)remain,
		    kernel_lost ? " (kernel ESP gone, CHILD rekey 1s)" : "");
	}
	ikev2_sa_start_polling_timer(sa);
	natt_start_natk(sa);
	ikev2_sa_insert(sa);
	ikev2_resume_save(sa);

	rc_free(local);
	rc_free(remote);
	return 0;

 fail:
	if (local)
		rc_free(local);
	if (remote)
		rc_free(remote);
	if (conf)
		rcf_free_remote(conf);
	if (sa) {
		while (!IKEV2_CHILD_LIST_EMPTY(&sa->children)) {
			struct ikev2_child_sa *ch;

			ch = IKEV2_CHILD_LIST_FIRST(&sa->children);
			ikev2_remove_child(ch);
			ikev2_destroy_child_sa(ch);
		}
		ikev2_dispose_sa(sa);
	}
	return -1;
}

void
ikev2_resume_load(void)
{
	DIR *d;
	struct dirent *de;
	char path[320];
	int n = 0;

	resume_migrate_legacy();
	d = opendir(r2_resume_dir());
	if (!d) {
		plog(PLOG_INFO, PLOGLOC, 0, "resume: no dumps loaded\n");
		return;
	}
	while ((de = readdir(d)) != NULL) {
		if (de->d_name[0] == '.')
			continue;
		snprintf(path, sizeof(path), "%s/%s", r2_resume_dir(),
		    de->d_name);
		if (restore_one(path) == 0)
			n++;
		else
			plog(PLOG_INTWARN, PLOGLOC, 0,
			    "resume: load failed %s (kept)\n", de->d_name);
	}
	closedir(d);
	if (n)
		plog(PLOG_INFO, PLOGLOC, 0, "resumed %d IKE_SA(s)\n", n);
	else
		plog(PLOG_INFO, PLOGLOC, 0, "resume: no dumps loaded\n");
}
