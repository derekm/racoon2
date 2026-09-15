/*
 * iked/ikev2_resume_rec.c — resume-dump record wire format.
 *
 * Moved out of ikev2_resume.c: the record layer is pure
 * (libracoon-only: vmbuf + rc_net), so resumetest can compile it
 * standalone and exercise save/load, truncation, and garbage input
 * without an iked instance.
 */
#include <config.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>

#include "racoon.h"
#include "vmbuf.h"
#include "rc_net.h"
#include "ikev2_resume_rec.h"

void
r2rs_key_from_vchar(struct r2rs_key *k, const rc_vchar_t *v)
{
	memset(k, 0, sizeof(*k));
	if (!v || v->l == 0)
		return;
	if ((size_t)v->l > R2RS_MAXKEY)
		k->len = R2RS_MAXKEY;
	else
		k->len = (uint16_t)v->l;
	memcpy(k->data, v->v, k->len);
}

rc_vchar_t *
r2rs_key_to_vchar(const struct r2rs_key *k)
{
	if (!k->len)
		return NULL;
	/* a corrupt len on disk would read past data[]; r2rs_validate()
	 * rejects it before we get here, but keep the cap as a
	 * second line of defense. */
	if (k->len > R2RS_MAXKEY)
		return NULL;
	return rc_vnew(k->data, k->len);
}

void
r2rs_sa_to_wire(const struct sockaddr *sa, uint16_t *family, uint16_t *port,
    uint8_t addr[16])
{
	memset(addr, 0, 16);
	*family = 0;
	*port = 0;
	if (!sa)
		return;
	*family = sa->sa_family;
	if (sa->sa_family == AF_INET) {
		const struct sockaddr_in *in = (const struct sockaddr_in *)sa;
		*port = ntohs(in->sin_port);
		memcpy(addr, &in->sin_addr, 4);
	} else if (sa->sa_family == AF_INET6) {
		const struct sockaddr_in6 *in6 =
		    (const struct sockaddr_in6 *)sa;
		*port = ntohs(in6->sin6_port);
		memcpy(addr, &in6->sin6_addr, 16);
	}
}

struct sockaddr *
r2rs_wire_to_sa(uint16_t family, uint16_t port, const uint8_t addr[16])
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
	return rcs_sadup((const struct sockaddr *)&ss);
}

void
r2rs_filename_in(char *buf, size_t buflen, const char *dir,
    const uint8_t i_ck[8], const uint8_t r_ck[8])
{
	snprintf(buf, buflen,
	    "%s/%02x%02x%02x%02x%02x%02x%02x%02x-%02x%02x%02x%02x%02x%02x%02x%02x",
	    dir,
	    i_ck[0], i_ck[1], i_ck[2], i_ck[3],
	    i_ck[4], i_ck[5], i_ck[6], i_ck[7],
	    r_ck[0], r_ck[1], r_ck[2], r_ck[3],
	    r_ck[4], r_ck[5], r_ck[6], r_ck[7]);
}

int
r2rs_validate(const struct r2rs_sa *rec)
{
	uint32_t i;

	if (!rec)
		return -1;
	if (rec->magic != R2RS_MAGIC || rec->version != R2RS_VERSION)
		return -1;
	if (rec->nchild > R2RS_MAXCHILD)
		return -1;
	/* keys: len must fit data[]; anything else is a corrupt dump. */
	{
		const struct r2rs_key *keys[] = {
		    &rec->sk_d, &rec->sk_ai, &rec->sk_ar, &rec->sk_ei,
		    &rec->sk_er, &rec->sk_pi, &rec->sk_pr,
		    &rec->n_i, &rec->n_r, &rec->id_i, &rec->id_r,
		};
		size_t nk = sizeof(keys) / sizeof(keys[0]);
		for (i = 0; i < nk; i++)
			if (keys[i]->len > R2RS_MAXKEY)
				return -1;
	}
	/* child records: same key/size discipline plus a sane SPI
	 * pair (in+out are always both present after IKE_AUTH). */
	for (i = 0; i < rec->nchild; i++) {
		const struct r2rs_child *c = &rec->child[i];
		if (c->in_spi == 0 || c->out_spi == 0)
			return -1;
		if (c->lease_af != 0 && c->lease_af != AF_INET &&
		    c->lease_af != AF_INET6)
			return -1;
	}
	return 0;
}
