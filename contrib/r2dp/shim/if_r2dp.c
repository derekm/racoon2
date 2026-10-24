/*
 * lib/if_r2dp.c -- racoon2 SAD/SPD backend that speaks the r2dp control
 * protocol to an external forwarder (e.g. the DPDK dataplane).
 *
 * Select with:  ./configure --with-km-backend=r2dp --with-r2dp=<prefix>
 *
 * This file is a pure translation layer: struct rcpfk_msg <-> struct
 * r2dp_sa/r2dp_sp.  racoon's rc_type enums are converted to IANA IKEv2
 * transform ids / IP protocol numbers on the way out and back on the way
 * in, so the forwarder never sees racoon2 internals.
 *
 * Semantics deliberately match if_pfkeyv2.c: requests complete
 * asynchronously on rc->so (the forwarder's reply is what fires the
 * rcpfk_cb callbacks), PFK_FLAG_WAITREPLY is honoured with a scratch
 * container for unrelated messages, and error replies surface as
 * rcpfk_handler() == -1 with rc->eno set.  Keys are never copied back
 * into rc.
 *
 * Distributed under the same terms as racoon2 (see COPYRIGHT).
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "vmbuf.h"
#include "rc_type.h"
#include "if_pfkeyv2.h"

#include <r2dp/proto.h>
#include <r2dp/client.h>

#ifndef UDP_ENCAP_ESPINUDP
#define UDP_ENCAP_ESPINUDP 2
#endif

uint32_t rc_spirange_min = 0x00000100;
uint32_t rc_spirange_max = 0x0fffffff;

static struct rcpfk_cb *cb;
static struct r2dp_hello_ack caps;
static int have_caps;

static void
km_seterror(struct rcpfk_msg *rc, int eno, const char *fmt, ...)
{
	va_list ap;

	rc->eno = eno;
	va_start(ap, fmt);
	vsnprintf(rc->estr, sizeof(rc->estr), fmt, ap);
	va_end(ap);
}

/* ------------------------------------------------ racoon <-> wire enums */
static int
enc_to_wire(int t)
{
	switch (t) {
	case 0:				return 0;	/* AH: none */
	case RCT_ALG_DES3_CBC:		return R2DP_ENCR_3DES;
	case RCT_ALG_NULL_ENC:		return R2DP_ENCR_NULL;
	case RCT_ALG_RIJNDAEL_CBC:
	case RCT_ALG_AES128_CBC:
	case RCT_ALG_AES192_CBC:
	case RCT_ALG_AES256_CBC:	return R2DP_ENCR_AES_CBC;
	case RCT_ALG_AES_CTR:		return R2DP_ENCR_AES_CTR;
	case RCT_ALG_AES_CCM8:		return R2DP_ENCR_AES_CCM_8;
	case RCT_ALG_AES_CCM:		return R2DP_ENCR_AES_CCM_12;
	case RCT_ALG_AES_CCM16:		return R2DP_ENCR_AES_CCM_16;
	case RCT_ALG_AES_GCM8:		return R2DP_ENCR_AES_GCM_8;
	case RCT_ALG_AES_GCM12:		return R2DP_ENCR_AES_GCM_12;
	case RCT_ALG_AES_GCM:		return R2DP_ENCR_AES_GCM_16;
	case RCT_ALG_CHACHA20_POLY1305:	return R2DP_ENCR_CHACHA20_POLY1305;
	}
	return -1;
}

static int
integ_to_wire(int t)
{
	switch (t) {
	case 0:
	case RCT_ALG_NON_AUTH:		return R2DP_INTEG_NONE;
	case RCT_ALG_HMAC_MD5:		return R2DP_INTEG_HMAC_MD5_96;
	case RCT_ALG_HMAC_SHA1:		return R2DP_INTEG_HMAC_SHA1_96;
	case RCT_ALG_AES_XCBC:		return R2DP_INTEG_AES_XCBC_96;
	case RCT_ALG_AES_CMAC:		return R2DP_INTEG_AES_CMAC_96;
	case RCT_ALG_HMAC_SHA2_256:	return R2DP_INTEG_HMAC_SHA2_256_128;
	case RCT_ALG_HMAC_SHA2_384:	return R2DP_INTEG_HMAC_SHA2_384_192;
	case RCT_ALG_HMAC_SHA2_512:	return R2DP_INTEG_HMAC_SHA2_512_256;
	}
	return -1;
}

static int
enc_from_wire(int w)
{
	switch (w) {
	case R2DP_ENCR_3DES:		return RCT_ALG_DES3_CBC;
	case R2DP_ENCR_NULL:		return RCT_ALG_NULL_ENC;
	case R2DP_ENCR_AES_CBC:		return RCT_ALG_RIJNDAEL_CBC;
	case R2DP_ENCR_AES_CTR:		return RCT_ALG_AES_CTR;
	case R2DP_ENCR_AES_CCM_8:	return RCT_ALG_AES_CCM8;
	case R2DP_ENCR_AES_CCM_12:	return RCT_ALG_AES_CCM;
	case R2DP_ENCR_AES_CCM_16:	return RCT_ALG_AES_CCM16;
	case R2DP_ENCR_AES_GCM_8:	return RCT_ALG_AES_GCM8;
	case R2DP_ENCR_AES_GCM_12:	return RCT_ALG_AES_GCM12;
	case R2DP_ENCR_AES_GCM_16:	return RCT_ALG_AES_GCM;
	case R2DP_ENCR_CHACHA20_POLY1305: return RCT_ALG_CHACHA20_POLY1305;
	}
	return 0;
}

static int
integ_from_wire(int w)
{
	switch (w) {
	case R2DP_INTEG_HMAC_MD5_96:	return RCT_ALG_HMAC_MD5;
	case R2DP_INTEG_HMAC_SHA1_96:	return RCT_ALG_HMAC_SHA1;
	case R2DP_INTEG_AES_XCBC_96:	return RCT_ALG_AES_XCBC;
	case R2DP_INTEG_AES_CMAC_96:	return RCT_ALG_AES_CMAC;
	case R2DP_INTEG_HMAC_SHA2_256_128: return RCT_ALG_HMAC_SHA2_256;
	case R2DP_INTEG_HMAC_SHA2_384_192: return RCT_ALG_HMAC_SHA2_384;
	case R2DP_INTEG_HMAC_SHA2_512_256: return RCT_ALG_HMAC_SHA2_512;
	}
	return RCT_ALG_NON_AUTH;
}

static int
proto_to_wire(int satype)
{
	switch (satype) {
	case RCT_SATYPE_ESP:	return R2DP_PROTO_ESP;
	case RCT_SATYPE_AH:	return R2DP_PROTO_AH;
	case RCT_SATYPE_IPCOMP:	return R2DP_PROTO_IPCOMP;
	}
	return -1;
}

static int
proto_from_wire(int p)
{
	switch (p) {
	case R2DP_PROTO_ESP:	return RCT_SATYPE_ESP;
	case R2DP_PROTO_AH:	return RCT_SATYPE_AH;
	case R2DP_PROTO_IPCOMP:	return RCT_SATYPE_IPCOMP;
	}
	return 0;
}

static int
mode_to_wire(int m)
{
	return m == RCT_IPSM_TRANSPORT ? R2DP_MODE_TRANSPORT :
	       m == RCT_IPSM_TUNNEL ? R2DP_MODE_TUNNEL : -1;
}

static int
mode_from_wire(int m)
{
	return m == R2DP_MODE_TRANSPORT ? RCT_IPSM_TRANSPORT :
	       m == R2DP_MODE_TUNNEL ? RCT_IPSM_TUNNEL : 0;
}

static int
dir_to_wire(int d)
{
	return d == RCT_DIR_INBOUND ? R2DP_DIR_IN :
	       d == RCT_DIR_OUTBOUND ? R2DP_DIR_OUT :
	       d == RCT_DIR_FWD ? R2DP_DIR_FWD : -1;
}

static int
dir_from_wire(int d)
{
	return d == R2DP_DIR_IN ? RCT_DIR_INBOUND :
	       d == R2DP_DIR_OUT ? RCT_DIR_OUTBOUND :
	       d == R2DP_DIR_FWD ? RCT_DIR_FWD : 0;
}

static int
act_to_wire(int a)
{
	switch (a) {
	case RCT_ACT_AUTO_IPSEC:	return R2DP_ACT_PROTECT;
	case RCT_ACT_DISCARD:		return R2DP_ACT_DISCARD;
	case RCT_ACT_NONE:		return R2DP_ACT_BYPASS;
	}
	return -1;	/* incl. RCT_ACT_STATIC_IPSEC, as if_pfkeyv2.c */
}

static int
act_from_wire(int a)
{
	return a == R2DP_ACT_PROTECT ? RCT_ACT_AUTO_IPSEC :
	       a == R2DP_ACT_DISCARD ? RCT_ACT_DISCARD :
	       a == R2DP_ACT_BYPASS ? RCT_ACT_NONE : 0;
}

static int
level_to_wire(int l)
{
	return l == RCT_IPSL_USE ? R2DP_LVL_USE :
	       l == RCT_IPSL_UNIQUE ? R2DP_LVL_UNIQUE : R2DP_LVL_REQUIRE;
}

static int
level_from_wire(int l)
{
	return l == R2DP_LVL_USE ? RCT_IPSL_USE :
	       l == R2DP_LVL_UNIQUE ? RCT_IPSL_UNIQUE : RCT_IPSL_REQUIRE;
}

static int
protos_to_wire(int satype)
{
	switch (satype) {
	case RCT_SATYPE_ESP:		return R2DP_SPP_ESP;
	case RCT_SATYPE_AH:		return R2DP_SPP_AH;
	case RCT_SATYPE_IPCOMP:		return R2DP_SPP_IPCOMP;
	case RCT_SATYPE_AH_ESP:		return R2DP_SPP_AH | R2DP_SPP_ESP;
	case RCT_SATYPE_AH_IPCOMP:	return R2DP_SPP_AH | R2DP_SPP_IPCOMP;
	case RCT_SATYPE_ESP_IPCOMP:	return R2DP_SPP_ESP | R2DP_SPP_IPCOMP;
	case RCT_SATYPE_AH_ESP_IPCOMP:	return R2DP_SPP_AH | R2DP_SPP_ESP | R2DP_SPP_IPCOMP;
	}
	return -1;
}

static int
protos_from_wire(int m)
{
	switch (m) {
	case R2DP_SPP_ESP:		return RCT_SATYPE_ESP;
	case R2DP_SPP_AH:		return RCT_SATYPE_AH;
	case R2DP_SPP_IPCOMP:		return RCT_SATYPE_IPCOMP;
	case R2DP_SPP_AH | R2DP_SPP_ESP: return RCT_SATYPE_AH_ESP;
	case R2DP_SPP_AH | R2DP_SPP_IPCOMP: return RCT_SATYPE_AH_IPCOMP;
	case R2DP_SPP_ESP | R2DP_SPP_IPCOMP: return RCT_SATYPE_ESP_IPCOMP;
	case R2DP_SPP_AH | R2DP_SPP_ESP | R2DP_SPP_IPCOMP: return RCT_SATYPE_AH_ESP_IPCOMP;
	}
	return 0;
}

/* ------------------------------------------------------------ lifecycle */
int
rcpfk_init(struct rcpfk_msg *rc, struct rcpfk_cb *cb0)
{
	const char *role = getenv("R2DP_ROLE");	/* "iked" | "spmd" | unset */
	uint32_t r = R2DP_ROLE_UNSPEC;
	int fd, e;

	cb = cb0;
	have_caps = 0;
	rc->so = -1;
	if (role)
		r = strcmp(role, "iked") == 0 ? R2DP_ROLE_IKED :
		    strcmp(role, "spmd") == 0 ? R2DP_ROLE_SPMD : R2DP_ROLE_UNSPEC;
	if ((fd = r2dp_connect(NULL)) < 0) {
		km_seterror(rc, -fd, "r2dp connect: %s", strerror(-fd));
		return -1;
	}
	if ((e = r2dp_hello(fd, r, &caps)) < 0) {
		km_seterror(rc, -e, "r2dp hello: %s", strerror(-e));
		close(fd);
		return -1;
	}
	have_caps = 1;
	rc->so = fd;
	return 0;
}

int
rcpfk_clean(struct rcpfk_msg *rc)
{
	cb = NULL;
	have_caps = 0;
	if (rc->so >= 0)
		close(rc->so);
	rc->so = -1;
	return 0;
}

int
rcpfk_supported_enc(int algtype)
{
	int w = enc_to_wire(algtype);

	if (w < 0)
		return 0;
	return have_caps ? r2dp_cap(caps.enc_caps, w) : 1;
}

int
rcpfk_supported_auth(int algtype)
{
	int w = integ_to_wire(algtype);

	if (w < 0)
		return 0;
	return have_caps ? r2dp_cap(caps.integ_caps, w) : 1;
}

/* ----------------------------------------------------------------- send */
/*
 * XFRM-native flow selectors.  mark/if_id restrict which traffic a state or
 * policy applies to; a forwarder that ignored them would apply the policy to
 * MORE traffic than configured, so refuse instead of dropping them silently.
 * (offload_ifname/ifindex/flags are only an optimisation hint -- the loopback
 * backend ignores them too -- so they are deliberately not an error.)
 */
static int
reject_xfrm_native(struct rcpfk_msg *rc)
{
#ifdef RCPFK_ABI_VERSION
	if (rc->mark || rc->mark_mask || rc->if_id) {
		km_seterror(rc, EOPNOTSUPP,
		    "mark/if_id selectors are not supported by the r2dp backend");
		return -1;
	}
#else
	(void)rc;
#endif
	return 0;
}

static int
km_send(struct rcpfk_msg *rc, unsigned type, uint32_t flags,
    const void *body, size_t blen, const void *tail, size_t tlen)
{
	int r;

	if (rc->so < 0) {
		km_seterror(rc, EBADF, "r2dp not connected");
		return -1;
	}
	if (reject_xfrm_native(rc))
		return -1;
	if ((r = r2dp_send(rc->so, type, rc->seq, 0, flags, body, blen,
	    tail, tlen)) < 0) {
		km_seterror(rc, -r, "r2dp send %s: %s", r2dp_msg_name(type),
		    strerror(-r));
		return -1;
	}
	return 0;
}

static int
pack_addr(struct rcpfk_msg *rc, struct r2dp_addr *a, struct sockaddr *sa)
{
	int r = r2dp_addr_from_sa(a, sa);

	if (r < 0) {
		km_seterror(rc, -r, "unsupported address family");
		return -1;
	}
	return 0;
}

/*
 * Build the wire SA from rc.  strict != 0 (ADD/UPDATE) requires every
 * algorithm to translate; lookups (GETSPI/DEL/GET) only need the key.
 */
static int
pack_sa(struct rcpfk_msg *rc, struct r2dp_sa *sa, int strict)
{
	int p, m, e, i;

	memset(sa, 0, sizeof(*sa));
	if ((p = proto_to_wire(rc->satype)) < 0) {
		km_seterror(rc, EINVAL, "invalid satype=%d", rc->satype);
		return -1;
	}
	if (p == R2DP_PROTO_IPCOMP) {
		km_seterror(rc, EOPNOTSUPP, "IPComp not supported by r2dp");
		return -1;
	}
	m = mode_to_wire(rc->samode);
	e = enc_to_wire(rc->enctype);
	i = integ_to_wire(rc->authtype);
	if (strict && (m < 0 || e < 0 || i < 0)) {
		km_seterror(rc, EINVAL, "unsupported samode=%d enctype=%d authtype=%d",
		    rc->samode, rc->enctype, rc->authtype);
		return -1;
	}
	if (rc->enckeylen > R2DP_MAX_KEY || rc->authkeylen > R2DP_MAX_KEY) {
		km_seterror(rc, EINVAL, "key too long (%zu/%zu)", rc->enckeylen,
		    rc->authkeylen);
		return -1;
	}
	sa->proto = (uint8_t)p;
	sa->mode = m < 0 ? 0 : (uint8_t)m;
	sa->enc = e < 0 ? 0 : (uint8_t)e;
	sa->integ = i < 0 ? 0 : (uint8_t)i;
	sa->spi = rc->spi;
	sa->reqid = rc->reqid;
	sa->saflags = (rc->saflags & SADB_X_SAFLAGS_ESN) ? R2DP_SAF_ESN : 0;
	sa->wsize = rc->wsize;
	sa->spi_min = rc_spirange_min;
	sa->spi_max = rc_spirange_max;
	sa->natt_type = rc->natt_type ? R2DP_NATT_ESPINUDP : R2DP_NATT_NONE;
	sa->natt_sport = rc->natt_sport;
	sa->natt_dport = rc->natt_dport;
	sa->enckeylen = (uint16_t)rc->enckeylen;
	sa->authkeylen = (uint16_t)rc->authkeylen;
	sa->lft_hard_time = rc->lft_hard_time;
	sa->lft_hard_bytes = rc->lft_hard_bytes;
	sa->lft_soft_time = rc->lft_soft_time;
	sa->lft_soft_bytes = rc->lft_soft_bytes;
	if (pack_addr(rc, &sa->src, rc->sa_src) || pack_addr(rc, &sa->dst, rc->sa_dst) ||
	    pack_addr(rc, &sa->natoa_src, rc->sa_natoa_src) ||
	    pack_addr(rc, &sa->natoa_dst, rc->sa_natoa_dst))
		return -1;
	return 0;
}

static int
send_sa(struct rcpfk_msg *rc, unsigned type, int with_keys)
{
	struct r2dp_sa sa;
	uint8_t tail[2 * R2DP_MAX_KEY];
	size_t tl = 0;

	if (pack_sa(rc, &sa, with_keys))
		return -1;
	if (with_keys) {
		if ((rc->enckeylen && !rc->enckey) || (rc->authkeylen && !rc->authkey)) {
			km_seterror(rc, EINVAL, "missing key material");
			return -1;
		}
		if (rc->enckeylen)
			memcpy(tail, rc->enckey, rc->enckeylen);
		if (rc->authkeylen)
			memcpy(tail + rc->enckeylen, rc->authkey, rc->authkeylen);
		tl = rc->enckeylen + rc->authkeylen;
	}
	{
		int r = km_send(rc, type, with_keys ? 0 : R2DP_HF_NOKEYS,
		    &sa, sizeof(sa), tail, tl);
		memset(tail, 0, sizeof(tail));	/* don't leave keys on the stack */
		return r;
	}
}

int rcpfk_send_getspi(struct rcpfk_msg *rc) { return send_sa(rc, R2DP_GETSPI, 0); }
int rcpfk_send_update(struct rcpfk_msg *rc) { return send_sa(rc, R2DP_SA_UPDATE, 1); }
int rcpfk_send_add(struct rcpfk_msg *rc)    { return send_sa(rc, R2DP_SA_ADD, 1); }
int rcpfk_send_delete(struct rcpfk_msg *rc) { return send_sa(rc, R2DP_SA_DEL, 0); }
int rcpfk_send_get(struct rcpfk_msg *rc)    { return send_sa(rc, R2DP_SA_GET, 0); }

/* SPD ------------------------------------------------------------------ */
static int
send_sp(struct rcpfk_msg *rc, unsigned type, uint32_t spflags, int strict)
{
	struct r2dp_sp sp;
	int d, a, pr;

	memset(&sp, 0, sizeof(sp));
	d = dir_to_wire(rc->dir);
	a = act_to_wire(rc->pltype);
	if (strict && (d < 0 || a < 0)) {
		km_seterror(rc, EINVAL, "invalid dir=%d pltype=%d", rc->dir, rc->pltype);
		return -1;
	}
	sp.dir = d < 0 ? 0 : (uint8_t)d;
	sp.action = a < 0 ? 0 : (uint8_t)a;
	if (a == R2DP_ACT_PROTECT) {
		int m = mode_to_wire(rc->samode);

		pr = protos_to_wire(rc->satype);
		if (strict && (m < 0 || pr < 0)) {
			km_seterror(rc, EINVAL, "invalid samode=%d satype=%d",
			    rc->samode, rc->satype);
			return -1;
		}
		sp.mode = m < 0 ? 0 : (uint8_t)m;
		sp.protos = pr < 0 ? 0 : (uint8_t)pr;
		if (pack_addr(rc, &sp.tun_src, rc->sa_src) ||
		    pack_addr(rc, &sp.tun_dst, rc->sa_dst))
			return -1;
	}
	sp.slid = rc->slid;
	sp.reqid = rc->reqid;
	sp.flags = spflags;
	sp.ul_proto = rc->ul_proto;
	sp.pref_src = rc->pref_src;
	sp.pref_dst = rc->pref_dst;
	sp.level = (uint8_t)level_to_wire(rc->ipsec_level);
	sp.lft_hard_time = rc->lft_hard_time;
	sp.lft_hard_bytes = rc->lft_hard_bytes;
	memcpy(sp.tag, rc->tag_name, sizeof(sp.tag) < sizeof(rc->tag_name) ?
	    sizeof(sp.tag) : sizeof(rc->tag_name));
	sp.tag[sizeof(sp.tag) - 1] = '\0';
	if (pack_addr(rc, &sp.sel_src, rc->sp_src) || pack_addr(rc, &sp.sel_dst, rc->sp_dst))
		return -1;
	return km_send(rc, type, 0, &sp, sizeof(sp), NULL, 0);
}

int rcpfk_send_spdadd(struct rcpfk_msg *rc)    { return send_sp(rc, R2DP_SP_ADD, 0, 1); }
int rcpfk_send_spdupdate(struct rcpfk_msg *rc) { return send_sp(rc, R2DP_SP_ADD, R2DP_SPF_UPDATE, 1); }
int rcpfk_send_spddelete(struct rcpfk_msg *rc) { return send_sp(rc, R2DP_SP_DEL, 0, 0); }
int rcpfk_send_spddelete2(struct rcpfk_msg *rc){ return send_sp(rc, R2DP_SP_DEL, 0, 0); }
int rcpfk_send_spdget(struct rcpfk_msg *rc)    { return send_sp(rc, R2DP_SP_GET, 0, 0); }
int rcpfk_send_spddump(struct rcpfk_msg *rc)   { return send_sp(rc, R2DP_SP_DUMP, 0, 0); }

/* No-ops / unsupported, mirroring the loopback backend where applicable. */
int rcpfk_send_register(struct rcpfk_msg *rc)  { (void)rc; return 0; }	/* HELLO replaces it */
int rcpfk_send_acquire(struct rcpfk_msg *rc)   { (void)rc; return 0; }	/* M4 */
int
rcpfk_send_migrate(struct rcpfk_msg *rc)
{
	km_seterror(rc, EOPNOTSUPP, "migrate not supported by r2dp");
	return -1;
}

/* -------------------------------------------------------------- receive */
static void
unpack_addr(const struct r2dp_addr *a, struct sockaddr_storage *st,
    struct sockaddr **out)
{
	*out = (r2dp_addr_to_sa(a, st) == 0) ? (struct sockaddr *)st : NULL;
}

static void
unpack_sa(struct rcpfk_msg *rc, const struct r2dp_sa *sa)
{
	rc->spi = sa->spi;
	rc->reqid = sa->reqid;
	rc->satype = (uint8_t)proto_from_wire(sa->proto);
	rc->samode = (uint8_t)mode_from_wire(sa->mode);
	rc->enctype = (uint8_t)enc_from_wire(sa->enc);
	rc->authtype = (uint8_t)integ_from_wire(sa->integ);
	rc->saflags = (sa->saflags & R2DP_SAF_ESN) ? SADB_X_SAFLAGS_ESN : 0;
	rc->wsize = sa->wsize;
	rc->natt_type = sa->natt_type ? UDP_ENCAP_ESPINUDP : 0;
	rc->natt_sport = sa->natt_sport;
	rc->natt_dport = sa->natt_dport;
	rc->lft_hard_time = sa->lft_hard_time;
	rc->lft_hard_bytes = sa->lft_hard_bytes;
	rc->lft_soft_time = sa->lft_soft_time;
	rc->lft_soft_bytes = sa->lft_soft_bytes;
	rc->lft_current_alloc = sa->cur_alloc;
	rc->lft_current_add = sa->cur_add;
	rc->lft_current_use = sa->cur_use;
	rc->lft_current_bytes = sa->cur_bytes;
	rc->expired = sa->expired;
	/*
	 * Key material is never copied out of the forwarder, and the caller's
	 * own enckey/authkey fields are left alone: a send-then-WAITREPLY
	 * caller reuses rc, and wiping its key pointers here would break its
	 * next ADD/UPDATE.
	 */
	unpack_addr(&sa->src, &rc->sa_src_storage, &rc->sa_src);
	unpack_addr(&sa->dst, &rc->sa_dst_storage, &rc->sa_dst);
	unpack_addr(&sa->natoa_src, &rc->sa_natoa_src_storage, &rc->sa_natoa_src);
	unpack_addr(&sa->natoa_dst, &rc->sa_natoa_dst_storage, &rc->sa_natoa_dst);
}

static void
unpack_sp(struct rcpfk_msg *rc, const struct r2dp_sp *sp)
{
	rc->slid = sp->slid;
	rc->reqid = sp->reqid;
	rc->dir = (uint8_t)dir_from_wire(sp->dir);
	rc->pltype = (uint8_t)act_from_wire(sp->action);
	rc->samode = (uint8_t)mode_from_wire(sp->mode);
	rc->satype = (uint8_t)protos_from_wire(sp->protos);
	rc->ipsec_level = (uint8_t)level_from_wire(sp->level);
	rc->ul_proto = sp->ul_proto;
	rc->pref_src = sp->pref_src;
	rc->pref_dst = sp->pref_dst;
	rc->lft_hard_time = sp->lft_hard_time;
	rc->lft_hard_bytes = sp->lft_hard_bytes;
	memset(rc->tag_name, 0, sizeof(rc->tag_name));
	memcpy(rc->tag_name, sp->tag, sizeof(rc->tag_name) < sizeof(sp->tag) ?
	    sizeof(rc->tag_name) : sizeof(sp->tag));
	rc->tag_name[sizeof(rc->tag_name) - 1] = '\0';
	unpack_addr(&sp->sel_src, &rc->sp_src_storage, &rc->sp_src);
	unpack_addr(&sp->sel_dst, &rc->sp_dst_storage, &rc->sp_dst);
	unpack_addr(&sp->tun_src, &rc->sa_src_storage, &rc->sa_src);
	unpack_addr(&sp->tun_dst, &rc->sa_dst_storage, &rc->sa_dst);
}

/* Parse one validated message into rc and run the matching callback. */
static int
dispatch(struct rcpfk_msg *rc, const struct r2dp_msg *m)
{
	int (*fn)(struct rcpfk_msg *) = NULL;

	if (m->h.status != 0) {
		km_seterror(rc, (int)m->h.status, "r2dp %s: %s",
		    r2dp_msg_name(m->h.type), strerror((int)m->h.status));
		return -1;
	}
	rc->seq = m->h.seq;
	switch (m->h.type) {
	case R2DP_GETSPI: case R2DP_SA_ADD: case R2DP_SA_UPDATE:
	case R2DP_SA_DEL: case R2DP_SA_GET: case R2DP_EXPIRE: case R2DP_ACQUIRE:
		unpack_sa(rc, r2dp_msg_sa(m));
		break;
	case R2DP_SP_ADD: case R2DP_SP_DEL: case R2DP_SP_GET: case R2DP_SP_DUMP:
		unpack_sp(rc, r2dp_msg_sp(m));
		break;
	default:
		return 0;	/* HELLO_ACK etc.: nothing for iked/spmd */
	}
	if (cb == NULL)
		return 0;
	switch (m->h.type) {
	case R2DP_GETSPI:    fn = cb->cb_getspi; break;
	case R2DP_SA_ADD:    fn = cb->cb_add; break;
	case R2DP_SA_UPDATE: fn = cb->cb_update; break;
	case R2DP_SA_DEL:    fn = cb->cb_delete; break;
	case R2DP_SA_GET:    fn = cb->cb_get; break;
	case R2DP_EXPIRE:    fn = cb->cb_expire; break;
	case R2DP_ACQUIRE:   fn = cb->cb_acquire; break;
	case R2DP_SP_ADD:    fn = cb->cb_spdadd ? cb->cb_spdadd : cb->cb_spdupdate; break;
	case R2DP_SP_DEL:    fn = rc->slid ? cb->cb_spddelete2 : cb->cb_spddelete;
	                     if (!fn) fn = cb->cb_spddelete2 ? cb->cb_spddelete2 : cb->cb_spddelete;
	                     break;
	case R2DP_SP_GET:    fn = cb->cb_spdget; break;
	case R2DP_SP_DUMP:   fn = cb->cb_spddump; break;
	}
	return fn ? fn(rc) : 0;
}

static int
recv_one(struct rcpfk_msg *rc, struct r2dp_msg *m)
{
	int r = r2dp_recv(rc->so, m);

	if (r == -ENOSYS)
		return 1;	/* unknown type from a newer forwarder: skip */
	if (r < 0) {
		km_seterror(rc, -r, "r2dp recv: %s", strerror(-r));
		return -1;
	}
	return 0;
}

int
rcpfk_handler(struct rcpfk_msg *rc)
{
	struct r2dp_msg m;
	struct rcpfk_msg scratch;
	struct pollfd pfd;
	int n, r, wait = (rc->flags & PFK_FLAG_WAITREPLY) != 0;

	if (rc->so < 0) {
		km_seterror(rc, EBADF, "r2dp not connected");
		return -1;
	}
	if (!wait) {
		if ((r = recv_one(rc, &m)) != 0)
			return r < 0 ? -1 : 0;
		return dispatch(rc, &m);
	}

	/*
	 * Send-then-read caller: consume until the reply carrying rc->seq,
	 * dispatching anything else (events, other requests' replies) with
	 * a scratch container so it is never parsed into rc.  A dump reply
	 * (R2DP_HF_MORE) is consumed to its last message.
	 */
	rc->flags &= ~PFK_FLAG_WAITREPLY;
	for (n = 0; n < 256; n++) {
		pfd.fd = rc->so;
		pfd.events = POLLIN;
		pfd.revents = 0;
		do {
			r = poll(&pfd, 1, 5000);
		} while (r < 0 && errno == EINTR);
		if (r <= 0) {
			km_seterror(rc, r == 0 ? ETIMEDOUT : errno,
			    "no r2dp reply to seq %u", rc->seq);
			return -1;
		}
		if ((r = recv_one(rc, &m)) < 0)
			return -1;
		if (r > 0)
			continue;
		if (m.h.seq == rc->seq && m.h.type != R2DP_EXPIRE &&
		    m.h.type != R2DP_ACQUIRE) {
			r = dispatch(rc, &m);
			if (r != 0 || !(m.h.flags & R2DP_HF_MORE))
				return r;
			continue;
		}
		memset(&scratch, 0, sizeof(scratch));
		scratch.so = rc->so;
		(void)dispatch(&scratch, &m);
	}
	km_seterror(rc, ETIMEDOUT, "no r2dp reply to seq %u", rc->seq);
	return -1;
}
