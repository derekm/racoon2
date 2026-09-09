/* IKEv2 session resume across iked restart: dump ESTABLISHED SAs,
 * leave kernel ESP in place, restore cookies/keys/message IDs. */

#include <config.h>

#include <sys/types.h>
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

/*
 * Dump expire_at as wall-clock unix. sched.xtime under FIXY2038PROBLEM
 * is seconds since sched_init(), not time(3). Mixing them made load
 * clamp remaining to 1s (bounce 2026-09-08 21:59).
 */
#define RESUME_UNIX_FLOOR	1000000000u	/* 2001-09-09 */

#ifndef RESUME_DIR
#define RESUME_DIR	"/var/run/racoon2/resume"
#endif

#define R2RS_MAGIC	0x52325253u	/* 'R2RS' */
#define R2RS_VERSION	1
#define R2RS_MAXKEY	64
#define R2RS_MAXSTR	64
#define R2RS_MAXCHILD	8

struct r2rs_key {
	uint16_t len;
	uint8_t data[R2RS_MAXKEY];
} __attribute__((packed));

struct r2rs_child {
	uint32_t in_spi;
	uint32_t out_spi;
	uint32_t expire_at;
	uint8_t satype;
	uint8_t lease_af;
	uint8_t lease_addr[16];
	char sl_index[R2RS_MAXSTR];
} __attribute__((packed));

struct r2rs_sa {
	uint32_t magic;
	uint32_t version;
	uint8_t i_ck[8];
	uint8_t r_ck[8];
	uint8_t is_initiator;
	uint8_t mobike;
	uint8_t frag;
	uint8_t behind_nat;
	uint8_t peer_behind_nat;
	uint8_t pad[3];
	uint32_t send_message_id;
	uint32_t recv_message_id;
	uint32_t ike_expire_at;
	int32_t encr;
	int32_t encrklen;
	int32_t prf;
	int32_t integr;
	int32_t dh_id;
	uint16_t local_family;
	uint16_t local_port;
	uint8_t local_addr[16];
	uint16_t remote_family;
	uint16_t remote_port;
	uint8_t remote_addr[16];
	char rm_index[R2RS_MAXSTR];
	struct r2rs_key sk_d, sk_ai, sk_ar, sk_ei, sk_er, sk_pi, sk_pr;
	struct r2rs_key n_i, n_r, id_i, id_r;
	uint32_t nchild;
	struct r2rs_child child[R2RS_MAXCHILD];
} __attribute__((packed));

static void
key_from_vchar(struct r2rs_key *k, rc_vchar_t *v)
{
	memset(k, 0, sizeof(*k));
	if (!v || v->l == 0)
		return;
	if (v->l > R2RS_MAXKEY)
		k->len = R2RS_MAXKEY;
	else
		k->len = (uint16_t)v->l;
	memcpy(k->data, v->v, k->len);
}

static rc_vchar_t *
key_to_vchar(const struct r2rs_key *k)
{
	if (!k->len)
		return NULL;
	return rc_vnew(k->data, k->len);
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

static void
sa_to_wire(struct sockaddr *sa, uint16_t *family, uint16_t *port,
    uint8_t addr[16])
{
	memset(addr, 0, 16);
	*family = 0;
	*port = 0;
	if (!sa)
		return;
	*family = sa->sa_family;
	if (sa->sa_family == AF_INET) {
		struct sockaddr_in *in = (struct sockaddr_in *)sa;
		*port = ntohs(in->sin_port);
		memcpy(addr, &in->sin_addr, 4);
	} else if (sa->sa_family == AF_INET6) {
		struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)sa;
		*port = ntohs(in6->sin6_port);
		memcpy(addr, &in6->sin6_addr, 16);
	}
}

static struct sockaddr *
wire_to_sa(uint16_t family, uint16_t port, const uint8_t addr[16])
{
	struct sockaddr_storage ss;

	memset(&ss, 0, sizeof(ss));
	if (family == AF_INET) {
		struct sockaddr_in *in = (struct sockaddr_in *)&ss;
		in->sin_family = AF_INET;
		in->sin_port = htons(port);
		memcpy(&in->sin_addr, addr, 4);
#ifdef HAVE_SA_LEN
		in->sin_len = sizeof(*in);
#endif
	} else if (family == AF_INET6) {
		struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)&ss;
		in6->sin6_family = AF_INET6;
		in6->sin6_port = htons(port);
		memcpy(&in6->sin6_addr, addr, 16);
#ifdef HAVE_SA_LEN
		in6->sin6_len = sizeof(*in6);
#endif
	} else
		return NULL;
	return rcs_sadup((struct sockaddr *)&ss);
}

static void
resume_filename(char *buf, size_t buflen, const uint8_t i_ck[8],
    const uint8_t r_ck[8])
{
	snprintf(buf, buflen,
	    RESUME_DIR
	    "/%02x%02x%02x%02x%02x%02x%02x%02x-%02x%02x%02x%02x%02x%02x%02x%02x",
	    i_ck[0], i_ck[1], i_ck[2], i_ck[3],
	    i_ck[4], i_ck[5], i_ck[6], i_ck[7],
	    r_ck[0], r_ck[1], r_ck[2], r_ck[3],
	    r_ck[4], r_ck[5], r_ck[6], r_ck[7]);
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
	nspi = htonl(spi_host);
	memcpy(prop + 1, &nspi, sizeof(nspi));
	p->prop = prop;
	return p;
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
	resume_filename(path, sizeof(path), sa->index.i_ck, sa->index.r_ck);
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
	sa_to_wire(sa->local, &lfam, &lport, rec.local_addr);
	rec.local_family = lfam;
	rec.local_port = lport;
	sa_to_wire(sa->remote, &rfam, &rport, rec.remote_addr);
	rec.remote_family = rfam;
	rec.remote_port = rport;
	if (sa->rmconf && sa->rmconf->rm_index)
		snprintf(rec.rm_index, sizeof(rec.rm_index), "%s",
		    rc_vmem2str(sa->rmconf->rm_index));
	key_from_vchar(&rec.sk_d, sa->sk_d);
	key_from_vchar(&rec.sk_ai, sa->sk_a_i);
	key_from_vchar(&rec.sk_ar, sa->sk_a_r);
	key_from_vchar(&rec.sk_ei, sa->sk_e_i);
	key_from_vchar(&rec.sk_er, sa->sk_e_r);
	key_from_vchar(&rec.sk_pi, sa->sk_p_i);
	key_from_vchar(&rec.sk_pr, sa->sk_p_r);
	key_from_vchar(&rec.n_i, sa->n_i);
	key_from_vchar(&rec.n_r, sa->n_r);
	key_from_vchar(&rec.id_i, sa->id_i);
	key_from_vchar(&rec.id_r, sa->id_r);

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
		if (ch->selector && ch->selector->sl_index)
			snprintf(rec.child[n].sl_index,
			    sizeof(rec.child[n].sl_index), "%s",
			    rc_vmem2str(ch->selector->sl_index));
		a = LIST_FIRST(&ch->lease_list);
		if (a) {
			rec.child[n].lease_af = (uint8_t)a->af;
			memcpy(rec.child[n].lease_addr, a->address, 16);
		}
		n++;
	}
	rec.nchild = (uint32_t)n;

	(void)mkdir("/var/run/racoon2", 0755);
	if (mkdir(RESUME_DIR, 0700) < 0 && errno != EEXIST) {
		isakmp_log(sa, 0, 0, 0, PLOG_INTERR, PLOGLOC,
			   "resume: mkdir %s failed\n", RESUME_DIR);
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
	int fd, i;
	time_t now = time(NULL);

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;
	if (read(fd, &rec, sizeof(rec)) != (ssize_t)sizeof(rec)) {
		close(fd);
		return -1;
	}
	close(fd);
	if (rec.magic != R2RS_MAGIC || rec.version != R2RS_VERSION)
		return -1;
	if (rec.nchild > R2RS_MAXCHILD)
		return -1;

	rmidx = rc_vnew(rec.rm_index, strlen(rec.rm_index));
	if (!rmidx || rcf_get_remotebyindex(rmidx, &conf) != 0) {
		plog(PLOG_INTERR, PLOGLOC, 0,
		    "resume: remote %s not in config\n", rec.rm_index);
		if (rmidx)
			rc_vfree(rmidx);
		return -1;
	}
	rc_vfree(rmidx);

	local = wire_to_sa(rec.local_family, rec.local_port, rec.local_addr);
	remote = wire_to_sa(rec.remote_family, rec.remote_port, rec.remote_addr);
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

	sa->sk_d = key_to_vchar(&rec.sk_d);
	sa->sk_a_i = key_to_vchar(&rec.sk_ai);
	sa->sk_a_r = key_to_vchar(&rec.sk_ar);
	sa->sk_e_i = key_to_vchar(&rec.sk_ei);
	sa->sk_e_r = key_to_vchar(&rec.sk_er);
	sa->sk_p_i = key_to_vchar(&rec.sk_pi);
	sa->sk_p_r = key_to_vchar(&rec.sk_pr);
	sa->n_i = key_to_vchar(&rec.n_i);
	sa->n_r = key_to_vchar(&rec.n_r);
	sa->id_i = key_to_vchar(&rec.id_i);
	sa->id_r = key_to_vchar(&rec.id_r);
	if (!sa->sk_d || !sa->sk_e_i || !sa->sk_e_r)
		goto fail;

	for (i = 0; i < (int)rec.nchild; i++) {
		struct ikev2_child_sa *ch;
		struct r2rs_child *c = &rec.child[i];
		time_t remain;
		struct rcf_addresspool *pool;
		struct rcf_address *addr;

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
		    "resumed IKE_SA %s children=%u msgid %u/%u ike_remain=%ld\n",
		    rcs_sa2str(sa->remote), rec.nchild,
		    rec.send_message_id, rec.recv_message_id, (long)remain);
	}
	ikev2_sa_start_polling_timer(sa);
	ikev2_sa_insert(sa);

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

	d = opendir(RESUME_DIR);
	if (!d)
		return;
	while ((de = readdir(d)) != NULL) {
		if (de->d_name[0] == '.')
			continue;
		snprintf(path, sizeof(path), RESUME_DIR "/%s", de->d_name);
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
