/* $Id$ */
/*
 * IKEv2 fragment reassembler unit test (same shape as resumetest:
 * check_PROGRAM, TAP-style printf + exit status).
 *
 * Exercises ikev2_frag_recv()/ikev2_frag_purge() standalone, with real
 * crypto (AES128-CBC + HMAC-SHA256 ICV, and AES-GCM AEAD), building
 * wire-valid SKF fragments exactly as ikev2_frag_send()/ikev2_encrypt()
 * would.  This is the reviewer gate: the reassembler (security-critical)
 * previously had zero automated coverage.
 *
 * Symbols below are normally provided by modules intentionally NOT
 * linked into this test (isakmp.o, sockmisc.o, ikev2_payload.o,
 * main.o); see the "standalone stubs" section.  Everything else comes
 * from the linked modules (encryptor/authenticator/keyed_hash/
 * crypto_openssl/str2val) and libracoon.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>

#include "vmbuf.h"
#include "rc_type.h"

#include "encryptor.h"
#include "keyed_hash.h"
/* authenticator.h comes in via isakmp_impl.h (it has no include guard) */
#include "isakmp_impl.h"
#include "ikev2.h"
#include "ikev2_impl.h"
#include "sockmisc.h"

#include "debug.h"

/*
 * ------------------------------------------------------------------
 * standalone stubs: symbols whose defining modules are not linked.
 * ikev2_frag.o needs isakmpstat (isakmp.o), debug_trace/trace_debug
 * (main.o), ikev2_encrypt/ikev2_decrypt (ikev2_payload.o),
 * isakmp_find_socket (isakmp.o), sendfromto (sockmisc.o) and
 * get_uint16/put_uint16/put_uint32 (isakmp.o).
 * ------------------------------------------------------------------
 */

struct isakmpstat isakmpstat;

int debug_trace = 0;

void
trace_debug(const char *location, const char *fmt, ...)
{
#ifdef FRAGTEST_TRACE
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "TRACE %s: ", location ? location : "?");
	vfprintf(stderr, fmt, ap);
	va_end(ap);
#else
	(void)location;
	(void)fmt;
#endif
}

/* ikev2_frag_send() calls these; ikev2_encrypt/decrypt are only used
 * by the send path, never by the reassembler under test. */
rc_vchar_t *
ikev2_encrypt(struct ikev2_sa *ike_sa, rc_vchar_t *payloads,
	      rc_vchar_t *aad)
{
	(void)ike_sa;
	(void)payloads;
	(void)aad;
	return NULL;
}

int
isakmp_find_socket(struct sockaddr *addr)
{
	(void)addr;
	return -1;
}

int
sendfromto(int sock, const void *buf, size_t buflen,
	   struct sockaddr *from, struct sockaddr *to, int hdrincl)
{
	(void)sock;
	(void)buf;
	(void)buflen;
	(void)from;
	(void)to;
	(void)hdrincl;
	return -1;
}

/* ikev2_frag_send() consults NAT-T state before baking a fragment's
 * RFC 3948 marker; the reassembler under test never runs that path, so
 * the stubs pin the test to the non-NAT-T branch (same as
 * ikev2_encrypt: send-path only). */
int
natt_check_udp_encap(struct sockaddr *remote, struct sockaddr *local)
{
	(void)remote;
	(void)local;
	return 0;
}

rc_vchar_t *
natt_set_non_esp_marker(rc_vchar_t *pkt)
{
	(void)pkt;
	return NULL;
}

uint16_t
get_uint16(const void *ptr)
{
	const uint8_t *p = ptr;

	return ((uint16_t)p[0] << 8)
		+ ((uint16_t)p[1] << 0);
}

void
put_uint16(void *ptr, uint32_t value)
{
	uint8_t *p = ptr;

	p[0] = (value >> 8);
	p[1] = (value >> 0);
}

void
put_uint32(void *ptr, uint32_t value)
{
	uint8_t *p = ptr;

	p[0] = (value >> 24);
	p[1] = (value >> 16);
	p[2] = (value >> 8);
	p[3] = (value >> 0);
}

/* logging stubs: libracoon's plog requires rbuf state that only the
 * daemon's main() initializes; the test never needs real logging. */
char *
plog(int prio, const char *loc, struct rc_log *lg, const char *fmt, ...)
{
	(void)prio;
	(void)loc;
	(void)lg;
	(void)fmt;
	return NULL;
}

char *
plogdump(int prio, const char *loc, struct rc_log *lg,
	 const void *data, size_t len)
{
	(void)prio;
	(void)loc;
	(void)lg;
	(void)data;
	(void)len;
	return NULL;
}

const char *
plog_location(const char *file, int line, const char *func)
{
	(void)file;
	(void)line;
	(void)func;
	return "fragtest";
}

/* iked-side logging wrapper referenced by ikev2_decrypt_internal(); the
 * test never needs real logging, so no-op like addketest.c. */
void
isakmp_log(struct ikev2_sa *ike_sa, struct sockaddr *local,
	   struct sockaddr *remote, rc_vchar_t *msg, int query,
	   const char *loc, const char *fmt, ...)
{
	(void)ike_sa; (void)local; (void)remote; (void)msg;
	(void)query; (void)loc; (void)fmt;
}

/*
 * ------------------------------------------------------------------
 * test scaffolding
 * ------------------------------------------------------------------
 */

static int checks;
static int failures;

#define CHECK(cond, name)						\
	do {								\
		checks++;						\
		if (cond)						\
			printf("ok %d - %s\n", checks, (name));		\
		else {							\
			printf("not ok %d - %s\n", checks, (name));	\
			failures++;					\
		}							\
	} while (/*CONSTCOND*/0)

#define SKF	IKEV2_PAYLOAD_ENCRYPTED_AND_AUTHENTICATED_FRAGMENT

static struct keyed_hash *ctx_hash;	/* HMAC-SHA256 */
static struct authenticator *ctx_auth;

enum frag_mode { MODE_CBC = 0, MODE_GCM };

/*
 * Build one valid SKF fragment the way the real sender would:
 *   IKE hdr (28B, next_payload=SKF, length=total) +
 *   SKF hdr (8B; frag1 keeps the inner next_payload, others 0) +
 *   IV + ciphertext (+ 32B HMAC-SHA256 ICV for CBC).
 * Plaintext per fragment = chunk || padding, RFC 7296 style:
 * pad_len makes chunk+1+pad_len a multiple of the block size;
 * last plaintext byte is pad_len.  (GCM: no pad, one pad_len byte.)
 *
 * Returns malloc'd rc_vchar_t; caller frees.  If corrupt_icv,
 * flips the last ICV byte (fails HMAC check in the reassembler).
 */
static rc_vchar_t *
build_frag(struct ikev2_sa *sa, enum frag_mode mode, uint32_t msgid,
	   uint8_t inner_np, uint16_t frag_no, uint16_t total_frags,
	   const uint8_t *chunk, size_t chunk_len, int corrupt_icv,
	   int raw_plain)
{
	struct ikev2_header hdr;
	struct ikev2payl_encrypted_fragment skf;
	rc_vchar_t *iv = NULL, *key = NULL;
	rc_vchar_t *plain = NULL, *cipher = NULL;
	rc_vchar_t *auth = NULL;
	rc_vchar_t *pkt = NULL;
	uint8_t *p;
	size_t iv_len, icv_len, pad_len = 0, plain_len, payload_len, total_len;
	size_t prefix_len;
	int tag_len;
	int i;

	/* SPIs left zero-initialized; the reassembler doesn't inspect them */
	memset(&hdr, 0, sizeof(hdr));
	hdr.next_payload = SKF;
	hdr.version = IKEV2_VERSION;
	hdr.exchange_type = IKEV2EXCH_INFORMATIONAL;
	hdr.message_id = htonl(msgid);

	/* Finalize SKF header and IKE header *before* building the AEAD
	 * AAD: the receiver reconstructs AAD from the wire bytes, so the
	 * sender's AAD must match the bytes that will actually be sent. */
	memset(&skf, 0, sizeof(skf));
	skf.header.next_payload = (frag_no == 1) ? inner_np : 0;
	skf.header.header_byte_2 = 0;
	skf.fragment_number = htons(frag_no);
	skf.total_fragments = htons(total_frags);

	iv_len = encryptor_iv_length(sa->encryptor);
	tag_len = encryptor_icv_length(sa->encryptor);	/* 0: CBC path */
	icv_len = (tag_len > 0) ? (size_t)tag_len
				: (size_t)auth_output_length(sa->authenticator);

	/* plaintext: chunk || padding || pad_len byte (unless raw_plain,
	 * which means chunk already IS the full plaintext incl. pad byte) */
	if (raw_plain) {
		plain_len = chunk_len;
		plain = rc_vnew(chunk, chunk_len);
	} else if (mode == MODE_CBC) {
		int block = encryptor_block_length(sa->encryptor);
		pad_len = (size_t)(block - ((chunk_len + 1) % block));
		if (pad_len == (size_t)block)
			pad_len = 0;
	} else {
		pad_len = 0;
	}
	plain_len = chunk_len + pad_len + 1;
	plain = rc_vmalloc(plain_len);
	if (!plain)
		goto out;
	memcpy(plain->v, chunk, chunk_len);
	memset(plain->v + chunk_len, 0, pad_len);	/* padding bytes */
	plain->u[plain_len - 1] = (uint8_t)pad_len;	/* pad len field */

	iv = rc_vmalloc(iv_len);
	if (!iv)
		goto out;
	for (i = 0; i < (int)iv_len; i++)
		iv->u[i] = (uint8_t)(i + 1);

	/* payload_len is deterministic before encryption: CBC/GCM output
	 * length equals input length (GCM adds its tag into the
	 * ciphertext which is already counted via icv_len).  Finalize
	 * both headers first so the AEAD AAD (built from them) matches
	 * the wire bytes the receiver will see. */
	payload_len = sizeof(skf) + iv_len + plain_len + icv_len;
	put_uint16(&skf.header.payload_length, (uint32_t)payload_len);
	total_len = sizeof(hdr) + payload_len;
	put_uint32(&hdr.length, (uint32_t)total_len);

	/* encryptor_encrypt() takes (data, key, iv); skf wire layout is
	 * SKF hdr || IV || ciphertext[||tag]. */
	key = sa->sk_e_i;	/* is_initiator == 0: receiver uses sk_e_i */
	if (mode == MODE_GCM) {
		/* AAD = IKE hdr + SKF hdr */
		rc_vchar_t *aad;

		aad = rc_vmalloc(sizeof(hdr) + sizeof(skf));
		if (!aad)
			goto out;
		memcpy(aad->v, &hdr, sizeof(hdr));
		memcpy(aad->v + sizeof(hdr), &skf, sizeof(skf));
		cipher = encryptor_encrypt_aead(sa->encryptor, plain, key,
						iv, aad);
		rc_vfree(aad);
	} else {
		cipher = encryptor_encrypt(sa->encryptor, plain, key, iv);
	}
	if (!cipher)
		goto out;
	prefix_len = sizeof(hdr) + sizeof(skf) + iv_len + cipher->l;

	pkt = rc_vmalloc(total_len);
	if (!pkt)
		goto out;
	p = pkt->v;
	memcpy(p, &hdr, sizeof(hdr));
	p += sizeof(hdr);
	memcpy(p, &skf, sizeof(skf));
	p += sizeof(skf);
	memcpy(p, iv->v, iv_len);
	p += iv_len;
	memcpy(p, cipher->v, cipher->l);
	p += cipher->l;
	pkt->l = prefix_len;
	if (tag_len == 0) {	/* CBC: append ICV */
		auth = auth_calculate(sa->authenticator, sa->sk_a_i,
				      pkt->v, prefix_len);
		if (!auth)
			goto out;
		memcpy(p, auth->v, icv_len);
		pkt->l = total_len;
		if (corrupt_icv)
			pkt->u[total_len - 1] ^= 0x01;
	}
out:
	if (iv)
		rc_vfree(iv);
	if (plain)
		rc_vfree(plain);
	if (cipher)
		rc_vfree(cipher);
	if (auth)
		rc_vfree(auth);
	return pkt;
}

/* fresh SA with encryptor/authenticator keys installed */
static void
sa_setup(struct ikev2_sa *sa, enum frag_mode mode)
{
	memset(sa, 0, sizeof(*sa));
	sa->encryptor = (mode == MODE_GCM) ?
	    encryptor_new(&encr_aesgcm128) : encryptor_new(&encr_aes128);
	sa->authenticator = ctx_auth;
	sa->is_initiator = 0;
	/* sk_e_i: AES-128 key (16B) or AES-GCM-128 key+salt (20B); the
	 * GCM implementation needs keylen = 4 (salt) + 16 (AES) */
	sa->sk_e_i = rc_vnew("0123456789abcdef",
			     (mode == MODE_GCM) ? 20 : 16);
	sa->sk_a_i = rc_vnew("abcdefghijklmnopqrstuvwxyz012345", 32);
	sa->sk_e_r = NULL;

	sa->frag_chain = NULL;
}

static void
sa_teardown(struct ikev2_sa *sa)
{
	ikev2_frag_purge(sa);
	if (sa->sk_e_i)
		rc_vfree(sa->sk_e_i);
	if (sa->sk_a_i)
		rc_vfree(sa->sk_a_i);
	sa->sk_e_i = sa->sk_a_i = NULL;
}

static int
chain_count(struct ikev2_sa *sa)
{
	struct ikev2_frag_item *it;
	int n = 0;

	for (it = sa->frag_chain; it; it = it->next)
		n++;
	return n;
}

static int
chain_has_msgid(struct ikev2_sa *sa, uint32_t msgid)
{
	struct ikev2_frag_item *it;

	for (it = sa->frag_chain; it; it = it->next)
		if (it->msgid == msgid)
			return 1;
	return 0;
}

/* generic inner payload: 1-byte next_payload tag + N data bytes */
static void
inner_payload(uint8_t *buf, size_t buflen, uint8_t np)
{
	size_t i;

	buf[0] = np;
	for (i = 1; i < buflen; i++)
		buf[i] = (uint8_t)(i * 7 + np);
}

/*
 * ------------------------------------------------------------------
 * test cases
 * ------------------------------------------------------------------
 */

/* happy path: 3 CBC fragments, out-of-order arrival */
static void
test_happy_cbc(void)
{
	struct ikev2_sa sa;
	uint8_t inner[40];
	rc_vchar_t *pkt = NULL, *frags[3];
	uint32_t msgid = 0x11223344;
	size_t chunk_len[3] = { 10, 20, 10 };	/* 10+20+10 = 40 */
	int i, ok;

	sa_setup(&sa, MODE_CBC);
	inner_payload(inner, sizeof(inner), IKEV2_PAYLOAD_NOTIFY);
	for (i = 0; i < 3; i++)
		frags[i] = build_frag(&sa, MODE_CBC, msgid,
				      (i == 0) ? IKEV2_PAYLOAD_NOTIFY : 0,
				      i + 1, 3, inner + (i == 0 ? 0 :
				      (i == 1 ? 10 : 30)), chunk_len[i], 0, 0);

	/* out of order: 3, 1, 2 */
	ok = 1;
	pkt = ikev2_frag_recv(&sa, frags[2], NULL, NULL);
	if (pkt != NULL)
		ok = 0;
	pkt = ikev2_frag_recv(&sa, frags[0], NULL, NULL);
	if (pkt != NULL)
		ok = 0;
	pkt = ikev2_frag_recv(&sa, frags[1], NULL, NULL);
	if (pkt == NULL || pkt->l != sizeof(struct ikev2_header) + 40 ||
	    ((struct ikev2_header *)pkt->v)->next_payload !=
		IKEV2_PAYLOAD_NOTIFY ||
	    memcmp(pkt->v + sizeof(struct ikev2_header), inner, 40) != 0)
		ok = 0;
	/* header length is written with put_uint32 (network order) */
	if (pkt != NULL) {
		uint8_t *lenp = (uint8_t *)&((struct ikev2_header *)pkt->v)->length;
		uint32_t wirelen = ((uint32_t)lenp[0] << 24) |
			((uint32_t)lenp[1] << 16) |
			((uint32_t)lenp[2] << 8) | (uint32_t)lenp[3];
		if (wirelen != sizeof(struct ikev2_header) + 40)
			ok = 0;
	}
	CHECK(ok, "CBC happy-path reassembly (3 frags out-of-order)");
	if (pkt)
		rc_vfree(pkt);
	sa_teardown(&sa);
}

/* happy path: 3 GCM fragments (AEAD path, icv inside ciphertext) */
static void
test_happy_gcm(void)
{
	struct ikev2_sa sa;
	uint8_t inner[40];
	rc_vchar_t *pkt = NULL, *frags[3];
	uint32_t msgid = 0x55667788;
	size_t chunk_len[3] = { 10, 20, 10 };
	int i, ok;

	sa_setup(&sa, MODE_GCM);
	inner_payload(inner, sizeof(inner), IKEV2_PAYLOAD_NOTIFY);
	for (i = 0; i < 3; i++)
		frags[i] = build_frag(&sa, MODE_GCM, msgid,
				      (i == 0) ? IKEV2_PAYLOAD_NOTIFY : 0,
				      i + 1, 3, inner + (i == 0 ? 0 :
				      (i == 1 ? 10 : 30)), chunk_len[i], 0, 0);

	/* different order: 2, 3, 1 */
	ok = 1;
	pkt = ikev2_frag_recv(&sa, frags[1], NULL, NULL);
	if (pkt != NULL)
		ok = 0;
	pkt = ikev2_frag_recv(&sa, frags[2], NULL, NULL);
	if (pkt != NULL)
		ok = 0;
	pkt = ikev2_frag_recv(&sa, frags[0], NULL, NULL);
	if (pkt == NULL || pkt->l != sizeof(struct ikev2_header) + 40 ||
	    memcmp(pkt->v + sizeof(struct ikev2_header), inner, 40) != 0)
		ok = 0;
	CHECK(ok, "GCM happy-path reassembly (3 frags, AEAD tag)");
	if (pkt)
		rc_vfree(pkt);
	sa_teardown(&sa);
}

/* incomplete set returns NULL; completing it afterwards works */
static void
test_incomplete(void)
{
	struct ikev2_sa sa;
	uint8_t inner[30];
	rc_vchar_t *pkt = NULL, *f1, *f2, *f3;
	uint32_t msgid = 0x00000000;

	sa_setup(&sa, MODE_CBC);
	inner_payload(inner, sizeof(inner), IKEV2_PAYLOAD_NOTIFY);
	f1 = build_frag(&sa, MODE_CBC, msgid, IKEV2_PAYLOAD_NOTIFY, 1, 3,
			inner, 10, 0, 0);
	f2 = build_frag(&sa, MODE_CBC, msgid, 0, 2, 3, inner + 10, 10, 0, 0);
	f3 = build_frag(&sa, MODE_CBC, msgid, 0, 3, 3, inner + 20, 10, 0, 0);

	CHECK(ikev2_frag_recv(&sa, f1, NULL, NULL) == NULL,
	      "incomplete set returns NULL (1/3)");
	CHECK(ikev2_frag_recv(&sa, f2, NULL, NULL) == NULL,
	      "incomplete set returns NULL (2/3)");
	pkt = ikev2_frag_recv(&sa, f3, NULL, NULL);
	CHECK(pkt != NULL &&
	      pkt->l == sizeof(struct ikev2_header) + 30 &&
	      memcmp(pkt->v + sizeof(struct ikev2_header), inner, 30) == 0,
	      "incomplete set completes on last fragment");
	if (pkt)
		rc_vfree(pkt);
	sa_teardown(&sa);
}

/* duplicate fragment rejected AND not double-counted */
static void
test_duplicate(void)
{
	struct ikev2_sa sa;
	uint8_t inner[24];
	rc_vchar_t *pkt = NULL, *f1, *f2a, *f2b, *f3;
	uint32_t msgid = 0x01020304;

	sa_setup(&sa, MODE_CBC);
	inner_payload(inner, sizeof(inner), IKEV2_PAYLOAD_NOTIFY);
	f1 = build_frag(&sa, MODE_CBC, msgid, IKEV2_PAYLOAD_NOTIFY, 1, 3,
			inner, 8, 0, 0);
	f2a = build_frag(&sa, MODE_CBC, msgid, 0, 2, 3, inner + 8, 8, 0, 0);
	f2b = build_frag(&sa, MODE_CBC, msgid, 0, 2, 3, inner + 8, 8, 0, 0);
	f3 = build_frag(&sa, MODE_CBC, msgid, 0, 3, 3, inner + 16, 8, 0, 0);

	ikev2_frag_recv(&sa, f1, NULL, NULL);
	ikev2_frag_recv(&sa, f2a, NULL, NULL);
	CHECK(ikev2_frag_recv(&sa, f2b, NULL, NULL) == NULL,
	      "duplicate fragment rejected");
	pkt = ikev2_frag_recv(&sa, f3, NULL, NULL);
	CHECK(pkt != NULL &&
	      pkt->l == sizeof(struct ikev2_header) + 24 &&
	      memcmp(pkt->v + sizeof(struct ikev2_header), inner, 24) == 0,
	      "duplicate not double-counted (merge clean)");
	if (pkt)
		rc_vfree(pkt);
	sa_teardown(&sa);
}

/* metadata validation: frag_no==0, total_frags==0, frag_no>total,
 * total>64, payload_len too small, payload_len beyond packet */
static void
test_metadata(void)
{
	struct ikev2_sa sa;
	uint8_t inner[8];
	rc_vchar_t *p;

	sa_setup(&sa, MODE_CBC);
	inner_payload(inner, sizeof(inner), IKEV2_PAYLOAD_NOTIFY);

	p = build_frag(&sa, MODE_CBC, 0x11111111, IKEV2_PAYLOAD_NOTIFY,
		       0, 3, inner, 8, 0, 0);
	CHECK(ikev2_frag_recv(&sa, p, NULL, NULL) == NULL,
	      "frag_no == 0 rejected");
	rc_vfree(p);

	p = build_frag(&sa, MODE_CBC, 0x22222222, IKEV2_PAYLOAD_NOTIFY,
		       1, 0, inner, 8, 1, 0);
	CHECK(ikev2_frag_recv(&sa, p, NULL, NULL) == NULL,
	      "total_frags == 0 rejected");
	rc_vfree(p);

	p = build_frag(&sa, MODE_CBC, 0x33333333, IKEV2_PAYLOAD_NOTIFY,
		       2, 1, inner, 8, 1, 0);
	CHECK(ikev2_frag_recv(&sa, p, NULL, NULL) == NULL,
	      "frag_no > total_frags rejected");
	rc_vfree(p);

	p = build_frag(&sa, MODE_CBC, 0x44444444, IKEV2_PAYLOAD_NOTIFY,
		       1, IKEV2_MAX_FRAGS + 1, inner, 8, 0, 0);
	CHECK(ikev2_frag_recv(&sa, p, NULL, NULL) == NULL,
	      "total_frags > 64 rejected");
	rc_vfree(p);

	/* SKF payload_len smaller than overhead (8 + iv + icv + 1) */
	p = build_frag(&sa, MODE_CBC, 0x55555555, IKEV2_PAYLOAD_NOTIFY,
		       1, 3, inner, 8, 0, 0);
	if (p) {
		struct ikev2payl_encrypted_fragment *skf =
		    (struct ikev2payl_encrypted_fragment *)
		    ((struct ikev2_header *)p->v + 1);
		put_uint16(&skf->header.payload_length, 8 + 16 + 32 - 1);
	}
	CHECK(ikev2_frag_recv(&sa, p, NULL, NULL) == NULL,
	      "SKF payload_len below overhead rejected");
	rc_vfree(p);

	/* payload_len exceeding actual packet length */
	p = build_frag(&sa, MODE_CBC, 0x66666666, IKEV2_PAYLOAD_NOTIFY,
		       1, 3, inner, 8, 0, 0);
	if (p) {
		struct ikev2payl_encrypted_fragment *skf =
		    (struct ikev2payl_encrypted_fragment *)
		    ((struct ikev2_header *)p->v + 1);
		put_uint16(&skf->header.payload_length, 60000);
	}
	CHECK(ikev2_frag_recv(&sa, p, NULL, NULL) == NULL,
	      "SKF payload_len beyond packet rejected");
	rc_vfree(p);

	sa_teardown(&sa);
}

/* corrupt ICV on the CBC/HMAC path */
static void
test_bad_icv(void)
{
	struct ikev2_sa sa;
	uint8_t inner[8];
	rc_vchar_t *p;
	int before;

	sa_setup(&sa, MODE_CBC);
	inner_payload(inner, sizeof(inner), IKEV2_PAYLOAD_NOTIFY);
	p = build_frag(&sa, MODE_CBC, 0x77777777, IKEV2_PAYLOAD_NOTIFY,
		       1, 3, inner, 8, 1, 0);	/* corrupt ICV */
	before = isakmpstat.fail_integrity_check;
	CHECK(ikev2_frag_recv(&sa, p, NULL, NULL) == NULL,
	      "corrupt ICV rejected (HMAC path)");
	CHECK(isakmpstat.fail_integrity_check == before + 1,
	      "corrupt ICV counted in isakmpstat");
	rc_vfree(p);
	sa_teardown(&sa);
}

/* corrupt AEAD tag on the GCM path */
static void
test_bad_gcm_tag(void)
{
	struct ikev2_sa sa;
	uint8_t inner[8];
	rc_vchar_t *p;

	sa_setup(&sa, MODE_GCM);
	inner_payload(inner, sizeof(inner), IKEV2_PAYLOAD_NOTIFY);
	p = build_frag(&sa, MODE_GCM, 0x88888888, IKEV2_PAYLOAD_NOTIFY,
		       1, 3, inner, 8, 0, 0);
	if (p)
		p->u[p->l - 1] ^= 0x01;	/* last byte of AEAD tag */
	CHECK(ikev2_frag_recv(&sa, p, NULL, NULL) == NULL,
	      "corrupt AEAD tag rejected (GCM path)");
	rc_vfree(p);
	sa_teardown(&sa);
}

/* invalid padding: pad_length byte larger than plaintext */
static void
test_bad_padding(void)
{
	struct ikev2_sa sa;
	/* decrypted block = 16 bytes, all zero except last byte which
	 * is the pad length field; pad_length(0xa0)+1 > 16 -> reject.
	 * raw_plain=1: chunk is already the full plaintext */
	uint8_t block[16];
	rc_vchar_t *p;

	sa_setup(&sa, MODE_CBC);
	memset(block, 0, sizeof(block));
	block[15] = 0xa0;	/* pad length larger than plaintext */
	p = build_frag(&sa, MODE_CBC, 0x99999999, IKEV2_PAYLOAD_NOTIFY,
		       1, 2, block, sizeof(block), 0, 1);
	CHECK(ikev2_frag_recv(&sa, p, NULL, NULL) == NULL,
	      "invalid padding (pad_len > plaintext) rejected");
	rc_vfree(p);
	sa_teardown(&sa);
}

/* PMTU probe: larger total_frags resets the assembly in place */
static void
test_pmtu_reset(void)
{
	struct ikev2_sa sa;
	uint8_t inner[30], inner2[30];
	rc_vchar_t *pkt = NULL;
	uint32_t msgid = 0xabcdef01;
	rc_vchar_t *f1, *f2, *f3;
	int before;

	sa_setup(&sa, MODE_CBC);
	inner_payload(inner, sizeof(inner), IKEV2_PAYLOAD_NOTIFY);
	inner_payload(inner2, sizeof(inner2), 0);

	/* 2-fragment assembly: frag 1/2 received */
	f1 = build_frag(&sa, MODE_CBC, msgid, IKEV2_PAYLOAD_NOTIFY, 1, 2,
			inner, 15, 0, 0);
	ikev2_frag_recv(&sa, f1, NULL, NULL);
	rc_vfree(f1);

	/* 3-fragment PMTU probe arrives: resets to total=3 */
	f2 = build_frag(&sa, MODE_CBC, msgid, 0, 2, 3, inner2 + 10, 10, 0, 0);
	CHECK(ikev2_frag_recv(&sa, f2, NULL, NULL) == NULL &&
	      sa.frag_chain && sa.frag_chain->num_received == 1 &&
	      sa.frag_chain->total_fragments == 3,
	      "PMTU probe resets assembly to larger total_frags");
	before = sa.frag_chain->num_received;
	rc_vfree(f2);

	/* complete with 3-fragment parts; old 2-frag part must be gone */
	f1 = build_frag(&sa, MODE_CBC, msgid, 0, 1, 3, inner2, 10, 0, 0);
	f3 = build_frag(&sa, MODE_CBC, msgid, 0, 3, 3, inner2 + 20, 10, 0, 0);
	ikev2_frag_recv(&sa, f1, NULL, NULL);
	/* frag 2 already stored post-reset (num_received was 1) */
	pkt = ikev2_frag_recv(&sa, f3, NULL, NULL);
	CHECK(pkt != NULL &&
	      pkt->l == sizeof(struct ikev2_header) + 30 &&
	      memcmp(pkt->v + sizeof(struct ikev2_header), inner2, 30) == 0 &&
	      before == 1,
	      "PMTU reset discards old parts (no stale merge)");
	if (pkt)
		rc_vfree(pkt);
	rc_vfree(f1);
	rc_vfree(f3);
	sa_teardown(&sa);
}

/* eviction: 5th distinct msgid evicts the oldest assembly */
static void
test_eviction(void)
{
	struct ikev2_sa sa;
	uint8_t inner[8];
	rc_vchar_t *p;
	uint32_t msgid;
	int i, ok;

	sa_setup(&sa, MODE_CBC);
	inner_payload(inner, sizeof(inner), IKEV2_PAYLOAD_NOTIFY);

	for (i = 1; i <= 5; i++) {
		msgid = 0x1000 + i;
		p = build_frag(&sa, MODE_CBC, msgid, IKEV2_PAYLOAD_NOTIFY,
			       1, 2, inner, 8, 0, 0);
		if (i < 5)
			ikev2_frag_recv(&sa, p, NULL, NULL);
		else
			CHECK(ikev2_frag_recv(&sa, p, NULL, NULL) == NULL,
			      "5th msgid assembly accepted (eviction path)");
		rc_vfree(p);
	}

	ok = chain_count(&sa) == IKEV2_MAX_ASSEMBLIES &&
	     !chain_has_msgid(&sa, 0x1001) &&
	     chain_has_msgid(&sa, 0x1002) &&
	     chain_has_msgid(&sa, 0x1003) &&
	     chain_has_msgid(&sa, 0x1004) &&
	     chain_has_msgid(&sa, 0x1005);
	CHECK(ok, "MAX_ASSEMBLIES=4 eviction drops oldest (msgid 1)");
	sa_teardown(&sa);
}

/* expiry: stale assembly is dropped on next frag_recv */
static void
test_expiry(void)
{
	struct ikev2_sa sa;
	uint8_t inner[8];
	rc_vchar_t *p;

	sa_setup(&sa, MODE_CBC);
	inner_payload(inner, sizeof(inner), IKEV2_PAYLOAD_NOTIFY);

	p = build_frag(&sa, MODE_CBC, 0x77770001, IKEV2_PAYLOAD_NOTIFY,
		       1, 2, inner, 8, 0, 0);
	ikev2_frag_recv(&sa, p, NULL, NULL);
	rc_vfree(p);
	CHECK(sa.frag_chain != NULL, "assembly pending before expiry");

	/* age it out, then touch the chain */
	sa.frag_chain->timeout = time(NULL) - 10;
	p = build_frag(&sa, MODE_CBC, 0x77770002, IKEV2_PAYLOAD_NOTIFY,
		       1, 2, inner, 8, 0, 0);
	ikev2_frag_recv(&sa, p, NULL, NULL);
	rc_vfree(p);
	CHECK(sa.frag_chain == NULL ||
	      !chain_has_msgid(&sa, 0x77770001),
	      "expired assembly dropped on next frag_recv");
	CHECK(!chain_has_msgid(&sa, 0x77770001),
	      "expired msgid no longer in chain");
	sa_teardown(&sa);
}

/* purge: frees all pending assemblies and NULLs the chain */
static void
test_purge(void)
{
	struct ikev2_sa sa;
	uint8_t inner[8];
	rc_vchar_t *p;

	sa_setup(&sa, MODE_CBC);
	inner_payload(inner, sizeof(inner), IKEV2_PAYLOAD_NOTIFY);

	p = build_frag(&sa, MODE_CBC, 0xaaa00001, IKEV2_PAYLOAD_NOTIFY,
		       1, 3, inner, 8, 0, 0);
	ikev2_frag_recv(&sa, p, NULL, NULL);
	rc_vfree(p);
	p = build_frag(&sa, MODE_CBC, 0xaaa00002, IKEV2_PAYLOAD_NOTIFY,
		       1, 3, inner, 8, 0, 0);
	ikev2_frag_recv(&sa, p, NULL, NULL);
	rc_vfree(p);
	CHECK(chain_count(&sa) == 2, "two pending assemblies before purge");

	ikev2_frag_purge(&sa);
	CHECK(sa.frag_chain == NULL, "purge frees all and NULLs chain");

	ikev2_frag_purge(&sa);	/* must be a no-op */
	CHECK(sa.frag_chain == NULL, "purge on empty chain is a no-op");
	sa_teardown(&sa);
}

int
main(void)
{
	/* global crypto context: HMAC-SHA256 authenticator */
	ctx_hash = hmacsha256_new();
	if (!ctx_hash) {
		printf("1..0\n");
		printf("# SKIP: HMAC-SHA256 unavailable\n");
		return 0;
	}
	ctx_auth = keyedhash_authenticator(ctx_hash);

	test_happy_cbc();
	test_happy_gcm();
	test_incomplete();
	test_duplicate();
	test_metadata();
	test_bad_icv();
	test_bad_gcm_tag();
	test_bad_padding();
	test_pmtu_reset();
	test_eviction();
	test_expiry();
	test_purge();

	printf("1..%d\n", checks);
	if (failures) {
		printf("# FAILED %d of %d checks\n", failures, checks);
		return 1;
	}
	return 0;
}

