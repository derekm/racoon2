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
#include <stddef.h>
#include <string.h>
#include <stdio.h>

#include "racoon.h"
#include "vmbuf.h"
#include "rc_net.h"
#include "ikev2_resume_rec.h"

int
r2rs_key_from_vchar(struct r2rs_key *k, const rc_vchar_t *v)
{
	memset(k, 0, sizeof(*k));
	if (!v || v->l == 0)
		return 0;
	/* Refuse rather than truncate.  A restored SA must not come up
	 * with a prefix of SK_d or an ID and look complete. */
	if ((size_t)v->l > R2RS_MAXKEY)
		return -1;
	k->len = (uint16_t)v->l;
	memcpy(k->data, v->v, k->len);
	return 0;
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

/*
 * Legacy (v3..v6) on-disk layouts.  Every pre-v7 record shares the v7
 * header up to child[], but each child is 2 octets shorter (no dh_id,
 * inserted by v7 between esn and is_initiator), and the tail after the
 * child array grew per version:
 *   v3: nothing
 *   v4: resp_msgid(4) resp_len(2) resp_buf[2048]
 *   v5: resp_msgid(4) resp_len(2) resp_nfrags(2) resp_frag_len[8] resp_buf[4608]
 *   v6: v5 + cert_due(4)
 * The record is a raw packed struct, so an older dump can only be read
 * by re-expanding it into the current layout; matching sizes against
 * the current struct (what the loader used to do) rejected all of them.
 */
#define R2RS_V4_MAXRESP	2048
#define R2RS_LEG_CHILD	(sizeof(struct r2rs_child) - sizeof(uint16_t))
#define R2RS_LEG_HEAD	(offsetof(struct r2rs_sa, child))
#define R2RS_LEG_TAIL	(R2RS_LEG_HEAD + R2RS_MAXCHILD * R2RS_LEG_CHILD)
#define R2RS_V5_TAIL	(offsetof(struct r2rs_sa, cert_due) - \
			 offsetof(struct r2rs_sa, resp_msgid))

size_t
r2rs_wire_size(uint32_t version)
{
	switch (version) {
	case 3:
		return R2RS_LEG_TAIL;
	case 4:
		return R2RS_LEG_TAIL + 4 + 2 + R2RS_V4_MAXRESP;
	case 5:
		return R2RS_LEG_TAIL + R2RS_V5_TAIL;
	case 6:
		return R2RS_LEG_TAIL + R2RS_V5_TAIL + sizeof(uint32_t);
	case R2RS_VERSION:
		return sizeof(struct r2rs_sa);
	default:
		return 0;
	}
}

int
r2rs_parse(struct r2rs_sa *rec, const void *buf, size_t len)
{
	const uint8_t *p = buf;
	uint32_t magic, version;
	size_t want, off, i;
	const size_t dhoff = offsetof(struct r2rs_child, dh_id);

	if (!rec || !buf)
		return -1;
	memset(rec, 0, sizeof(*rec));
	if (len < 2 * sizeof(uint32_t))
		return -1;
	memcpy(&magic, p, sizeof(magic));
	memcpy(&version, p + sizeof(magic), sizeof(version));
	if (magic != R2RS_MAGIC)
		return -1;
	/* the length must be exactly the size that version wrote; a
	 * record whose version and size disagree is truncated or
	 * corrupt, never "a prefix of something newer". */
	want = r2rs_wire_size(version);
	if (want == 0 || len != want)
		return -1;
	if (version == R2RS_VERSION) {
		memcpy(rec, p, sizeof(*rec));
		return 0;
	}

	memcpy(rec, p, R2RS_LEG_HEAD);
	off = R2RS_LEG_HEAD;
	for (i = 0; i < R2RS_MAXCHILD; i++) {
		uint8_t *c = (uint8_t *)&rec->child[i];

		memcpy(c, p + off, dhoff);
		/* dh_id stays 0 (memset): pre-v7 never recorded the
		 * child's PFS group, so restore falls back to config. */
		memcpy(c + dhoff + sizeof(uint16_t), p + off + dhoff,
		    R2RS_LEG_CHILD - dhoff);
		off += R2RS_LEG_CHILD;
	}
	switch (version) {
	case 4: {
		uint16_t rlen;

		memcpy(&rec->resp_msgid, p + off, 4);
		memcpy(&rlen, p + off + 4, 2);
		if (rlen > R2RS_V4_MAXRESP)
			return -1;
		rec->resp_len = rlen;
		memcpy(rec->resp_buf, p + off + 6, R2RS_V4_MAXRESP);
		break;
	}
	case 5:
	case 6:
		memcpy(&rec->resp_msgid, p + off, R2RS_V5_TAIL);
		off += R2RS_V5_TAIL;
		if (version == 6)
			memcpy(&rec->cert_due, p + off, sizeof(rec->cert_due));
		break;
	default:
		break;
	}
	return 0;
}

int
r2rs_validate(const struct r2rs_sa *rec)
{
	uint32_t i;

	if (!rec)
		return -1;
	if (rec->magic != R2RS_MAGIC ||
	    rec->version > R2RS_VERSION ||
	    rec->version < 3)
		return -1;
	if (rec->resp_len > R2RS_MAXRESP)
		return -1;
	if (rec->resp_nfrags > R2RS_MAXFRAGS)
		return -1;
	if (rec->version >= 5) {	/* v5 introduced the fragment form */
		uint32_t f, total = 0;

		/* exactly one response form: whole packet (resp_len) or
		 * fragment list (resp_nfrags), never both.  Both zero is
		 * legal (no response armed yet). */
		if (rec->resp_len > 0 && rec->resp_nfrags > 0)
			return -1;
		for (f = 0; f < rec->resp_nfrags; f++) {
			if (rec->resp_frag_len[f] > R2RS_MAXFRAG)
				return -1;
			total += rec->resp_frag_len[f];
		}
		/* per-frag caps already bound total to MAXFRAGS*MAXFRAG ==
		 * MAXRESP; the check is belt and braces if the caps move. */
		if (total > R2RS_MAXRESP)
			return -1;
	}
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
		if (memchr(c->sl_index, '\0', R2RS_MAXSTR) == NULL)
			return -1;
		/* RFC 9370 ADDKE (v3): pending flag implies sane link */
		if (c->addke_pending &&
		    (c->addke_method == 0 ||
		     c->addke_link_len == 0 ||
		     c->addke_link_len > sizeof(c->addke_link)))
			return -1;
		if (c->addke_link_len > sizeof(c->addke_link))
			return -1;
		/* child role is a boolean (who created it); anything else is a
		 * corrupt dump.  Old v5 dumps have this byte 0 (peer-created). */
		if (c->is_initiator > 1)
			return -1;
	}
	/* strings must be NUL-terminated in-place: restore_one() and
	 * the child restore use strlen() on these fixed arrays, so an
	 * unterminated dump would over-read past the record. */
	if (memchr(rec->rm_index, '\0', R2RS_MAXSTR) == NULL)
		return -1;
	return 0;
}
