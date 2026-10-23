/*
 * addketest: RFC 9370 ADDKE ML-KEM-768 crypto self-test.
 *
 * Runs ikev2_addke_selftest() (keygen->encap->decap round-trip) and,
 * when the openssl CLI is available, cross-checks the EVP path against
 * `openssl pkeyutl -encap/-decap` so the racoon2 wrappers are verified
 * against the provider's own implementation (not just against
 * themselves).
 *
 * WITH_ADDKE builds only; the Makefile adds the target conditionally.
 */

#include "config.h"

#ifdef WITH_ADDKE

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/evp.h>
#include <openssl/ml_kem.h>
#include <openssl/x509.h>
#include <openssl/crypto.h>	/* OPENSSL_free */

#include "racoon.h"
#include "isakmp.h"
#include "isakmp_impl.h"
#include "ikev2.h"
#include "ikev2_impl.h"
#include "dhgroup.h"

/* logging stubs (same rationale as fragtest.c) */
char *
plog(int prio, const char *loc, struct rc_log *lg, const char *fmt, ...)
{
	(void)prio; (void)loc; (void)lg; (void)fmt;
	return NULL;
}

char *
plogdump(int prio, const char *loc, struct rc_log *lg,
	 const void *data, size_t len)
{
	(void)prio; (void)loc; (void)lg; (void)data; (void)len;
	return NULL;
}

const char *
plog_location(const char *file, int line, const char *func)
{
	(void)file; (void)line; (void)func;
	return "addketest";
}

/* iked-side symbols referenced by ikev2_addke.c but never invoked by
 * the crypto self-test; stub so the TU links standalone. */
struct isakmpstat isakmpstat;

/* TRACE() (debug.h) and eay_set_random() (crypto_impl.h) are referenced
 * by ikev2_addke.c's responder followup (which now mints a fresh per-round
 * link with random_bytes()); stub so the standalone TU links.  debug_trace
 * stays 0 so the trace calls are runtime no-ops. */
int debug_trace;

void
trace_debug(const char *location, const char *fmt, ...)
{
	(void)location; (void)fmt;
}

rc_vchar_t *
eay_set_random(uint32_t size)
{
	rc_vchar_t *buf = rc_vmalloc(size);

	if (buf) {
		uint32_t i;
		for (i = 0; i < size; i++)
			buf->u[i] = (uint8_t)(0xA0 + i);
	}
	return buf;
}

/* the followup-link tests below read back the last log line and the
 * notify the handler answered with */
static char last_log[256];
static int n_respond_error;
static unsigned int last_error_type;
static int n_rekey_complete;
static int n_child_install;	/* ikev2_child_addke_install() invocations */
static int child_install_fail;	/* make ikev2_child_addke_install() fail */

void
isakmp_log(struct ikev2_sa *ike_sa, struct sockaddr *local,
	   struct sockaddr *remote, rc_vchar_t *msg, int query,
	   const char *loc, const char *fmt, ...)
{
	va_list ap;

	(void)ike_sa; (void)local; (void)remote; (void)msg;
	(void)query; (void)loc;
	va_start(ap, fmt);
	vsnprintf(last_log, sizeof(last_log), fmt, ap);
	va_end(ap);
}

int
ikev2_respond_error(struct ikev2_sa *ike_sa, rc_vchar_t *msg,
		    struct sockaddr *remote, struct sockaddr *local,
		    unsigned int a, uint8_t *b, int c, unsigned int d,
		    void *e, size_t f)
{
	(void)ike_sa; (void)msg; (void)remote; (void)local;
	(void)a; (void)b; (void)c; (void)e; (void)f;
	++n_respond_error;
	last_error_type = d;
	return -1;
}

/* iked child/socket machinery referenced by ikev2_addke.c's followup
 * handler but never invoked by the crypto self-test; stubs so the TU
 * links standalone (same rationale as the symbols above). */
struct ikev2_child_sa *
ikev2_find_child_sa_by_spi(struct ikev2_sa *ike_sa, unsigned int proto,
			   uint32_t spi, enum peer_mine mine)
{
	(void)ike_sa; (void)proto; (void)spi; (void)mine;
	return NULL;
}

void
ikev2_child_delete(struct ikev2_child_sa *child_sa)
{
	(void)child_sa;
}

void
ikev2_initiator_rekey_finalize(struct ikev2_sa *ike_sa,
			       struct ikev2_child_sa *child_sa)
{
	(void)ike_sa; (void)child_sa;
}

/* iked-side packet machinery referenced by ikev2_addke.c's followup
 * handler but never invoked by the crypto self-test; stubs so the TU
 * links standalone (same rationale as above). */
uint16_t
get_uint16(const void *ptr)
{
	const uint8_t *p = ptr;
	return ((uint16_t)p[0] << 8) + ((uint16_t)p[1] << 0);
}

uint32_t
get_uint32(const void *ptr)
{
	const uint8_t *p = ptr;
	return ((uint32_t)p[0] << 24) + ((uint32_t)p[1] << 16) +
	       ((uint32_t)p[2] << 8) + ((uint32_t)p[3] << 0);
}

void
ikev2_payloads_init(struct ikev2_payloads *p)
{
	(void)p;
}

void
ikev2_payloads_push(struct ikev2_payloads *p, int type, rc_vchar_t *v,
		    int critical)
{
	(void)p; (void)type; (void)v; (void)critical;
}

void
ikev2_payloads_destroy(struct ikev2_payloads *p)
{
	(void)p;
}

rc_vchar_t *
ikev2_packet_construct(int exch_type, int flags, uint32_t message_id,
		       struct ikev2_sa *sa, struct ikev2_payloads *payl)
{
	/* the unit test drives the followup happy path, so return a real
	 * buffer the transmit-response stub frees, letting the handler
	 * advance the round cursor instead of failing at the reply */
	(void)exch_type; (void)flags; (void)message_id;
	(void)sa; (void)payl;
	return rc_vmalloc(1);
}

uint32_t
ikev2_request_id(struct ikev2_sa *sa)
{
	(void)sa;
	return 1;
}

rc_vchar_t *
ikev2_notify_payload(int proto, uint8_t *spi, int spi_size, int type,
		     uint8_t *data, size_t data_size)
{
	(void)proto; (void)spi; (void)spi_size; (void)type;
	(void)data; (void)data_size;
	return NULL;
}

struct sched *
sched_new(time_t tick, void (*func)(void *), void *param)
{
	(void)tick; (void)func; (void)param;
	return NULL;
}

void
sched_kill(struct sched *sc)
{
	(void)sc;
}

int
ikev2_transmit_response(struct ikev2_sa *sa, rc_vchar_t *pkt,
			struct sockaddr *local, struct sockaddr *remote)
{
	/* take ownership like the real path (handler expects the pkt to be
	 * consumed here); free so the unit test does not leak */
	(void)sa; (void)local; (void)remote;
	if (pkt)
		rc_vfree(pkt);
	return -1;
}

int
ikev2_transmit(struct ikev2_sa *sa, rc_vchar_t *pkt)
{
	/* consume like the real path; keep for followup_send success */
	(void)sa;
	if (pkt)
		rc_vfree(pkt);
	return 0;
}

void
ikev2_update_message_id(struct ikev2_sa *sa, uint32_t id, int is_response)
{
	(void)sa; (void)id; (void)is_response;
}

/* ikev2_followup_wakeup_next() (after the IKE_FOLLOWUP_KE window commit)
 * calls into the request queue; the crypto self-test never reaches it. */
struct ikev2_child_sa *
ikev2_choose_pending_child(struct ikev2_sa *sa, int initiator_only)
{
	(void)sa; (void)initiator_only;
	return NULL;
}

void
ikev2_wakeup_child_sa(struct ikev2_child_sa *child_sa)
{
	(void)child_sa;
}

int
ikev2_child_addke_install(struct ikev2_child_sa *child_sa)
{
	(void)child_sa;
	++n_child_install;
	return child_install_fail ? -1 : 0;
}

void
ikev2_child_addke_arm_timeout(struct ikev2_child_sa *child_sa)
{
	(void)child_sa;
}

/* classical-DH ADDKE round symbols (dh.c / ike_conf.c) are not part of the
 * standalone addketest link.  A deterministic fake group stands in for them
 * so the classical round engine -- keygen, followup completion and round
 * state teardown -- runs under ASan here (H1: the classical round used to
 * leave addke_dh_pub/addke_dh_priv dangling, and child teardown freed them
 * a second time).  The real group arithmetic is KATed in ndcppkats and
 * proven live in the netns matrix (i2ike-addke-fr3/fr7). */
#define FAKE_DH_ID	19	/* ECP256 transform id */
#define FAKE_DH_PUBLEN	64	/* x||y */
#define FAKE_DH_SSLEN	32
static uint8_t fake_dh_prime_bytes[FAKE_DH_SSLEN];
static rc_vchar_t fake_dh_prime = { FAKE_DH_SSLEN, { fake_dh_prime_bytes } };
static struct dhgroup fake_dh = { 0, &fake_dh_prime, 0, 0, NULL, NULL, NULL, NULL };
static struct algdef fake_dh_def;
static int fake_dh_compute_fail;
static int fake_dh_gen_count;

struct algdef *
ikev2_dhinfo(unsigned int id)
{
	if (id != FAKE_DH_ID)
		return NULL;
	fake_dh_def.transform_id = FAKE_DH_ID;
	fake_dh_def.definition = &fake_dh;
	return &fake_dh_def;
}

int
oakley_dh_generate(const struct dhgroup *dh, rc_vchar_t **pub,
    rc_vchar_t **priv)
{
	if (dh != &fake_dh)
		return -1;
	*pub = rc_vmalloc(FAKE_DH_PUBLEN);
	*priv = rc_vmalloc(FAKE_DH_SSLEN);
	if (!*pub || !*priv) {
		rc_vfree(*pub); rc_vfree(*priv);
		*pub = *priv = NULL;
		return -1;
	}
	memset((*pub)->v, 0x40 + fake_dh_gen_count, FAKE_DH_PUBLEN);
	memset((*priv)->v, 0x10 + fake_dh_gen_count, FAKE_DH_SSLEN);
	++fake_dh_gen_count;
	return 0;
}

/* Same ownership contract as dh.c: on failure *gxy is freed and NULL. */
int
oakley_dh_compute(const struct dhgroup *dh, rc_vchar_t *pub,
    rc_vchar_t *priv, rc_vchar_t *pub_p, rc_vchar_t **gxy)
{
	size_t i;

	(void)pub;
	*gxy = NULL;
	if (dh != &fake_dh || fake_dh_compute_fail || !priv || !pub_p ||
	    pub_p->l != FAKE_DH_PUBLEN)
		return -1;
	if ((*gxy = rc_vmalloc(FAKE_DH_SSLEN)) == NULL)
		return -1;
	for (i = 0; i < FAKE_DH_SSLEN; i++)
		(*gxy)->u[i] = priv->u[i] ^ pub_p->u[i];
	return 0;
}

size_t
dh_value_len(struct dhgroup *dhgrp)
{
	return dhgrp == &fake_dh ? FAKE_DH_PUBLEN : 0;
}

int
ikev2_rekey_responder_addke_round(struct ikev2_sa *sa, rc_vchar_t *ss,
				  rc_vchar_t *ct, uint32_t followup_msgid,
				  unsigned int ke_method)
{
	(void)sa; (void)ss; (void)ct; (void)followup_msgid; (void)ke_method;
	return 0;
}

int
ikev2_rekey_responder_addke_complete(struct ikev2_sa *sa, rc_vchar_t *sk,
				     rc_vchar_t *ct, uint32_t followup_msgid,
				     unsigned int ke_method)
{
	(void)sa; (void)sk; (void)ct; (void)followup_msgid; (void)ke_method;
	++n_rekey_complete;
	return -1;
}

uint32_t
ikev2_rekey_ikesa_init_followup_msgid(struct ikev2_sa *sa)
{
	(void)sa;
	return 0;
}

int
ikev2_rekey_ikesa_init_addke_complete(struct ikev2_sa *sa, rc_vchar_t *ct,
				      const uint8_t *link, size_t link_len)
{
	(void)sa; (void)ct; (void)link; (void)link_len;
	return -1;
}

void
ikev2_rekey_abandon_parked(struct ikev2_sa *sa)
{
	(void)sa;
}

static int fail;

#define CHECK(cond, what)						\
do {									\
	if (!(cond)) {							\
		fprintf(stderr, "FAIL: %s (line %d)\n", what, __LINE__); \
		fail = 1;						\
	} else {							\
		printf("ok: %s\n", what);				\
	}								\
} while (0)

extern int ikev2_addke_selftest(void);
extern int ikev2_addke_mlkem_keygen(unsigned int, rc_vchar_t **,
				    EVP_PKEY **);
extern int ikev2_addke_mlkem_encap(unsigned int, rc_vchar_t *,
				   rc_vchar_t **, rc_vchar_t **);
extern int ikev2_addke_mlkem_decap(EVP_PKEY *, rc_vchar_t *,
				   rc_vchar_t **);

static const char *prog = "/usr/bin/openssl";

/* write buf to tmpfile, return a malloc'd path (caller free) */
static char *
tmp_path(const char *base, const void *buf, size_t len)
{
	char tmpl[128];
	const char *dir = getenv("TMPDIR");
	if (dir == NULL)
		dir = "/tmp";
	snprintf(tmpl, sizeof(tmpl), "%s/%s-XXXXXX", dir, base);
	int fd = mkstemp(tmpl);
	if (fd < 0)
		return NULL;
	if (write(fd, buf, len) != (ssize_t)len) {
		close(fd);
		unlink(tmpl);
		return NULL;
	}
	close(fd);
	return strdup(tmpl);
}

/* pkeyutl -encap: secret out, ciphertext out. Returns 0 on success. */
static int
cli_encap(const char *pubfile, const char *secretfile,
	  const char *ctfile)
{
	pid_t pid;
	int status;

	pid = fork();
	if (pid < 0)
		return -1;
	if (pid == 0) {
		int devnull = open("/dev/null", O_WRONLY);
		if (devnull >= 0) {
			dup2(devnull, 1);
			dup2(devnull, 2);
		}
		execl(prog, prog, "pkeyutl", "-encap",
		      "-pubin", "-inkey", pubfile,
		      "-secret", secretfile, "-out", ctfile,
		      (char *)NULL);
		_exit(127);
	}
	if (waitpid(pid, &status, 0) < 0)
		return -1;
	return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
}

/* pkeyutl -decapsulate using a private key file.
 * Returns 0 on success; secret written to secretfile. */
static int
cli_decap(const char *privfile, const char *ctfile,
	  const char *secretfile)
{
	pid_t pid;
	int status;

	pid = fork();
	if (pid < 0)
		return -1;
	if (pid == 0) {
		int devnull = open("/dev/null", O_WRONLY);
		if (devnull >= 0) {
			dup2(devnull, 1);
			dup2(devnull, 2);
		}
		execl(prog, prog, "pkeyutl", "-decap",
		      "-inkey", privfile,
		      "-in", ctfile,
		      "-secret", secretfile,
		      (char *)NULL);
		_exit(127);
	}
	if (waitpid(pid, &status, 0) < 0)
		return -1;
	return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
}

/* openssl genpkey -algorithm <alg> -out privfile,
 * then pkey -pubout (DER) to pubfile.  Returns 0 on success. */
static int
cli_keygen(const char *alg, const char *privfile, const char *pubfile)
{
	pid_t pid;
	int status;

	pid = fork();
	if (pid < 0)
		return -1;
	if (pid == 0) {
		int devnull = open("/dev/null", O_WRONLY);
		if (devnull >= 0) {
			dup2(devnull, 1);
			dup2(devnull, 2);
		}
		execl(prog, prog, "genpkey", "-algorithm", alg,
		      "-out", privfile, (char *)NULL);
		_exit(127);
	}
	if (waitpid(pid, &status, 0) < 0)
		return -1;
	if (!(WIFEXITED(status) && WEXITSTATUS(status) == 0))
		return -1;

	pid = fork();
	if (pid < 0)
		return -1;
	if (pid == 0) {
		int devnull = open("/dev/null", O_WRONLY);
		if (devnull >= 0) {
			dup2(devnull, 1);
			dup2(devnull, 2);
		}
		execl(prog, prog, "pkey", "-in", privfile,
		      "-pubout", "-outform", "DER", "-out", pubfile,
		      (char *)NULL);
		_exit(127);
	}
	if (waitpid(pid, &status, 0) < 0)
		return -1;
	return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
}

/* read a file into a malloc'd buffer (caller free / rc-free) */
static rc_vchar_t *
read_file_rc(const char *path)
{
	FILE *f = fopen(path, "rb");
	unsigned char buf[8192];
	size_t n;
	if (f == NULL)
		return NULL;
	n = fread(buf, 1, sizeof(buf), f);
	fclose(f);
	return rc_vnew(buf, n);
}

/*
 * IKE_FOLLOWUP_KE responder: a followup whose N(ADDITIONAL_KEY_EXCHANGE)
 * link matches no pending ADDKE state must be answered STATE_NOT_FOUND
 * (RFC 9370 s2.2.4) and must not touch any pending state.  The message
 * is the decrypted form ikev2_input hands the handler: IKE header,
 * KEi(1), N(16441)(link).
 */
extern void ikev2_followup_ke_recv(struct ikev2_sa *, rc_vchar_t *,
				   struct sockaddr *, struct sockaddr *);

static rc_vchar_t *
followup_msg(unsigned int method, const rc_vchar_t *pub,
	     const void *link, size_t link_len)
{
	size_t ke_len = sizeof(struct ikev2payl_ke) + pub->l;
	size_t n_len = sizeof(struct ikev2payl_notify) + link_len;
	size_t total = sizeof(struct ikev2_header) + ke_len + n_len;
	rc_vchar_t *m = rc_vmalloc(total);
	struct ikev2_header *h;
	struct ikev2payl_ke *ke;
	struct ikev2payl_notify *n;

	if (!m)
		return NULL;
	memset(m->v, 0, total);
	h = (struct ikev2_header *)m->v;
	h->next_payload = IKEV2_PAYLOAD_KE;
	h->version = IKEV2_VERSION;
	h->exchange_type = IKEV2EXCH_IKE_FOLLOWUP_KE;
	h->flags = IKEV2FLAG_INITIATOR;
	h->message_id = htonl(3);
	h->length = htonl((uint32_t)total);
	ke = (struct ikev2payl_ke *)(h + 1);
	ke->header.next_payload = IKEV2_PAYLOAD_NOTIFY;
	ke->header.payload_length = htons((uint16_t)ke_len);
	ke->ke_h.dh_group_id = htons((uint16_t)method);
	memcpy(ke + 1, pub->v, pub->l);
	n = (struct ikev2payl_notify *)((uint8_t *)ke + ke_len);
	n->header.next_payload = IKEV2_NO_NEXT_PAYLOAD;
	n->header.payload_length = htons((uint16_t)n_len);
	n->nh.protocol_id = IKEV2_NOTIFY_PROTO_NONE;
	n->nh.spi_size = 0;
	n->nh.notify_message_type = htons(IKEV2_ADDITIONAL_KEY_EXCHANGE);
	memcpy(n + 1, link, link_len);
	return m;
}

static struct ikev2_child_sa *
pending_child(struct ikev2_sa *sa, unsigned int method, const char *link)
{
	struct ikev2_child_sa *c = calloc(1, sizeof(*c));

	if (!c)
		return NULL;
	c->parent = sa;
	c->addke_pending = 1;
	c->addke_method = method;
	c->addke_link = rc_vnew(link, strlen(link));
	IKEV2_CHILD_LIST_LINK(&sa->children, c);
	return c;
}

static void
followup_reset(void)
{
	last_log[0] = '\0';
	n_respond_error = 0;
	last_error_type = 0;
	n_rekey_complete = 0;
	n_child_install = 0;
}

static int
link_is(const struct ikev2_child_sa *c, const char *link)
{
	return c->addke_link && c->addke_link->l == strlen(link) &&
	       memcmp(c->addke_link->v, link, strlen(link)) == 0;
}

#define NOT_FOUND_ANSWERED()						\
	(n_respond_error == 1 &&					\
	 last_error_type == IKEV2_STATE_NOT_FOUND &&			\
	 strstr(last_log, "no pending ADDKE state for link") != NULL)

static void
followup_link_tests(void)
{
	const unsigned int m768 = IKEV2TRANSF_ADDKE_MLKEM768;
	rc_vchar_t *pub = NULL, *msg = NULL;
	EVP_PKEY *kp = NULL;
	struct ikev2_sa *sa;
	struct ikev2_child_sa *c1, *c2;
	struct sockaddr_in loc, rem;

	printf("--- IKE_FOLLOWUP_KE unknown link ---\n");
	memset(&loc, 0, sizeof(loc));
	memset(&rem, 0, sizeof(rem));
	loc.sin_family = rem.sin_family = AF_INET;
	CHECK(ikev2_addke_mlkem_keygen(m768, &pub, &kp) == 0 && pub,
	      "followup: keygen ML-KEM-768 KEi");
	if (!pub) {
		fail = 1;
		return;
	}
	sa = calloc(1, sizeof(*sa));
	if (!sa) {
		fail = 1;
		return;
	}
	IKEV2_CHILD_LIST_INIT(&sa->children);
	sa->recv_message_id = 3;

	/* 1. no pending ADDKE state at all */
	followup_reset();
	msg = followup_msg(m768, pub, "unknown-link", 12);
	ikev2_followup_ke_recv(sa, msg, (struct sockaddr *)&rem,
			       (struct sockaddr *)&loc);
	CHECK(NOT_FOUND_ANSWERED(),
	      "followup: no pending state -> STATE_NOT_FOUND");
	rc_vfree(msg);

	/* 2. a pending IKE-SA rekey is no licence for another link */
	followup_reset();
	sa->addke_rekey_pending = 1;
	sa->addke_rekey_link = rc_vnew("rekey-link", 10);
	msg = followup_msg(m768, pub, "other-link", 10);
	ikev2_followup_ke_recv(sa, msg, (struct sockaddr *)&rem,
			       (struct sockaddr *)&loc);
	CHECK(NOT_FOUND_ANSWERED() && n_rekey_complete == 0,
	      "followup: rekey pending, link mismatch -> STATE_NOT_FOUND, "
	      "rekey not completed");
	rc_vfree(msg);
	/* control: the rekey's own link reaches the rekey completion */
	followup_reset();
	msg = followup_msg(m768, pub, "rekey-link", 10);
	ikev2_followup_ke_recv(sa, msg, (struct sockaddr *)&rem,
			       (struct sockaddr *)&loc);
	CHECK(n_rekey_complete == 1 &&
	      strstr(last_log, "no pending ADDKE state") == NULL,
	      "followup: rekey link match -> rekey completion");
	rc_vfree(msg);
	sa->addke_rekey_pending = 0;
	rc_vfree(sa->addke_rekey_link);
	sa->addke_rekey_link = NULL;

	/* 3. two pending children of the same method: an unknown link is
	 * ambiguous and must not be bound to either */
	c1 = pending_child(sa, m768, "link-one");
	c2 = pending_child(sa, m768, "link-two");
	if (!c1 || !c2 || !c1->addke_link || !c2->addke_link) {
		fail = 1;
		return;
	}
	followup_reset();
	msg = followup_msg(m768, pub, "link-three", 10);
	ikev2_followup_ke_recv(sa, msg, (struct sockaddr *)&rem,
			       (struct sockaddr *)&loc);
	CHECK(NOT_FOUND_ANSWERED(),
	      "followup: ambiguous pending children -> STATE_NOT_FOUND");
	CHECK(link_is(c1, "link-one") && link_is(c2, "link-two") &&
	      c1->addke_sk == NULL && c2->addke_sk == NULL &&
	      c1->addke_pending && c2->addke_pending,
	      "followup: unknown link left both children untouched");
	rc_vfree(msg);

	/* control: an exact link selects that child (SK(1) accumulated),
	 * no error answered */
	followup_reset();
	msg = followup_msg(m768, pub, "link-two", 8);
	ikev2_followup_ke_recv(sa, msg, (struct sockaddr *)&rem,
			       (struct sockaddr *)&loc);
	CHECK(n_respond_error == 0 && c2->addke_sk != NULL &&
	      c2->addke_sk->l == OSSL_ML_KEM_SHARED_SECRET_BYTES &&
	      c1->addke_sk == NULL,
	      "followup: exact link -> that child, no error");
	rc_vfree(msg);

	IKEV2_CHILD_LIST_REMOVE(&sa->children, c1);
	IKEV2_CHILD_LIST_REMOVE(&sa->children, c2);
	rc_vfree(c1->addke_link);
	rc_vfree(c2->addke_link);
	rc_vfreez(c2->addke_sk);
	free(c1);
	free(c2);
	free(sa);
	rc_vfree(pub);
	EVP_PKEY_free(kp);
}

/* Multi-round ADDKE (RFC 9370 s2.2.1): the responder accumulates SK(1..n)
 * one round per IKE_FOLLOWUP_KE, in Transform Type order, and installs the
 * child only after the last round.  Each round's KE method must equal the
 * round's negotiated method (methods[round]); a mismatch is refused. */
static void
followup_multiround_tests(void)
{
	const unsigned int m512 = IKEV2TRANSF_ADDKE_MLKEM512;
	const unsigned int m768 = IKEV2TRANSF_ADDKE_MLKEM768;
	rc_vchar_t *pub512 = NULL, *pub768 = NULL;
	rc_vchar_t *msg = NULL;
	EVP_PKEY *kp512 = NULL, *kp768 = NULL;
	struct ikev2_sa *sa;
	struct ikev2_child_sa *c;
	struct sockaddr_in loc, rem;

	printf("--- IKE_FOLLOWUP_KE multi-round (2 rounds) ---\n");
	memset(&loc, 0, sizeof(loc));
	memset(&rem, 0, sizeof(rem));
	loc.sin_family = rem.sin_family = AF_INET;
	CHECK(ikev2_addke_mlkem_keygen(m512, &pub512, &kp512) == 0 && pub512,
	      "multi-round: keygen ML-KEM-512 (round 0)");
	CHECK(ikev2_addke_mlkem_keygen(m768, &pub768, &kp768) == 0 && pub768,
	      "multi-round: keygen ML-KEM-768 (round 1)");
	if (!pub512 || !pub768) {
		fail = 1;
		return;
	}
	sa = calloc(1, sizeof(*sa));
	if (!sa) {
		fail = 1;
		return;
	}
	IKEV2_CHILD_LIST_INIT(&sa->children);
	sa->recv_message_id = 3;

	c = calloc(1, sizeof(*c));
	if (!c) {
		fail = 1;
		return;
	}
	c->parent = sa;
	c->addke_pending = 1;
	c->addke_nrounds = 2;
	c->addke_round = 0;
	c->addke_methods[0] = m512;
	c->addke_methods[1] = m768;
	c->addke_link = rc_vnew("mround", 6);
	IKEV2_CHILD_LIST_LINK(&sa->children, c);

	/* round 0: method m512 accumulates SK(1); child still pending */
	followup_reset();
	n_child_install = 0;
	msg = followup_msg(m512, pub512, "mround", 6);
	ikev2_followup_ke_recv(sa, msg, (struct sockaddr *)&rem,
			       (struct sockaddr *)&loc);
	rc_vfree(msg);
	CHECK(n_respond_error == 0 && n_child_install == 0,
	      "multi-round: round 0 not installed, no error");
	CHECK(c->addke_round == 1 &&
	      c->addke_sk && c->addke_sk->l == OSSL_ML_KEM_SHARED_SECRET_BYTES,
	      "multi-round: round 0 accumulated SK(1), cursor advanced");
	/* RFC 9370 s2.2.4: a non-final response mints a FRESH link for the
	 * next round (the "mround" 6-byte probe must be replaced), so the
	 * next followup exact-matches the link the responder just issued. */
	CHECK(c->addke_link && c->addke_link->l == 16,
	      "multi-round: round-0 response minted a fresh (16 B) link");

	/* wrong method on round 1 is refused (methods[1]=m768) */
	followup_reset();
	msg = followup_msg(m512, pub512, "mround", 6);
	ikev2_followup_ke_recv(sa, msg, (struct sockaddr *)&rem,
			       (struct sockaddr *)&loc);
	rc_vfree(msg);
	CHECK(n_respond_error == 1 && last_error_type == IKEV2_STATE_NOT_FOUND,
	      "multi-round: round-1 method mismatch refused (STATE_NOT_FOUND)");

	/* round 1: method m768 completes the pair and installs */
	followup_reset();
	msg = followup_msg(m768, pub768, "mround", 6);
	ikev2_followup_ke_recv(sa, msg, (struct sockaddr *)&rem,
			       (struct sockaddr *)&loc);
	rc_vfree(msg);
	CHECK(n_child_install == 1,
	      "multi-round: final round (m768) triggers install");
	CHECK(n_respond_error == 0,
	      "multi-round: final round clean");

	IKEV2_CHILD_LIST_REMOVE(&sa->children, c);
	rc_vfree(c->addke_link);
	rc_vfreez(c->addke_sk);
	free(c);
	free(sa);
	rc_vfree(pub512);
	rc_vfree(pub768);
	EVP_PKEY_free(kp512);
	EVP_PKEY_free(kp768);
}

/* Initiator-side multi-round ADDKE driver: after each IKE_FOLLOWUP_KE
 * response, ikev2_initiator_followup_complete() decapsulates that round's
 * ciphertext with the round's keypair (addke_priv), appends SK to the
 * accumulated addke_sk, advances the round cursor, and when rounds remain
 * generates the next keypair and sends the next followup instead of
 * installing.  Only the final round installs the child. */
static void
initiator_multiround_tests(void)
{
	const unsigned int m512 = IKEV2TRANSF_ADDKE_MLKEM512;
	const unsigned int m768 = IKEV2TRANSF_ADDKE_MLKEM768;
	EVP_PKEY *kp0 = NULL;
	rc_vchar_t *pub0 = NULL, *ct0 = NULL, *ss0 = NULL;
	rc_vchar_t *ct1 = NULL;
	struct ikev2_sa *sa;
	struct ikev2_child_sa *c;

	printf("--- IKE_FOLLOWUP_KE initiator multi-round (2 rounds) ---\n");
	/* round-0 keypair: the initiator's KEi (= pub0) is what the
	 * responder encapsulates against; the responder's ciphertext ct0
	 * and its shared secret ss0 are the role we drive here */
	CHECK(ikev2_addke_mlkem_keygen(m512, &pub0, &kp0) == 0 && pub0 && kp0,
	      "init-mr: round-0 keygen (KEi)");
	if (!pub0 || !kp0) {
		fail = 1;
		return;
	}
	/* responder encapsulates against our KEi: ct0, ss0 */
	CHECK(ikev2_addke_mlkem_encap(m512, pub0, &ct0, &ss0) == 0
	      && ct0 && ss0,
	      "init-mr: responder encapsulate against KEi -> ct0/ss0");
	if (!ct0 || !ss0) {
		fail = 1;
		return;
	}

	sa = calloc(1, sizeof(*sa));
	c = calloc(1, sizeof(*c));
	if (!sa || !c) {
		fail = 1;
		return;
	}
	IKEV2_CHILD_LIST_INIT(&sa->children);
	c->parent = sa;
	c->addke_pending = 1;
	c->addke_nrounds = 2;
	c->addke_round = 0;
	c->addke_methods[0] = m512;
	c->addke_methods[1] = m768;
	c->addke_link = rc_vnew("imag", 4);
	c->addke_priv = kp0;	/* round-0 keypair */
	c->addke_method = m512;	/* round-0 method (set by round_keygen in prod) */
	IKEV2_CHILD_LIST_LINK(&sa->children, c);

	n_child_install = 0;
	followup_reset();
	CHECK(ikev2_initiator_followup_complete(c, ct0) == 0,
	      "init-mr: complete round 0 (decap SK(1))");
	CHECK(c->addke_sk && c->addke_sk->l == OSSL_ML_KEM_SHARED_SECRET_BYTES &&
	      memcmp(c->addke_sk->v, ss0->v, ss0->l) == 0,
	      "init-mr: accumulated SK(1) equals responder decap");
	CHECK(c->addke_round == 1 && n_child_install == 0,
	      "init-mr: round 0 advanced, not yet installed");
	CHECK(c->addke_priv != NULL &&
	      c->addke_method == m768,
	      "init-mr: round-1 keypair generated, method advanced");

	/* round-1: encapsulate against the new round-1 pub (addke_priv) */
	{
		unsigned char rawpub[4096];
		size_t rawlen = sizeof(rawpub);
		rc_vchar_t *peerpub1, *ss1 = NULL;

		CHECK(EVP_PKEY_get_raw_public_key(
		    (EVP_PKEY *)c->addke_priv, rawpub, &rawlen) > 0
		    && rawlen == OSSL_ML_KEM_768_PUBLIC_KEY_BYTES,
		    "init-mr: round-1 raw pub is ML-KEM-768");
		peerpub1 = rc_vnew(rawpub, rawlen);
		CHECK(ikev2_addke_mlkem_encap(m768, peerpub1, &ct1,
					      &ss1) == 0 && ct1,
		      "init-mr: encapsulate round-1 ct");
		if (ss1)
			rc_vfree(ss1);
		rc_vfree(peerpub1);
	}
	if (!ct1) {
		fail = 1;
		return;
	}
	followup_reset();
	CHECK(ikev2_initiator_followup_complete(c, ct1) == 0,
	      "init-mr: complete round 1");
	CHECK(c->addke_sk && c->addke_sk->l == 2 * OSSL_ML_KEM_SHARED_SECRET_BYTES,
	      "init-mr: SK(1)+SK(2) accumulated (64 bytes)");
	CHECK(n_child_install == 1,
	      "init-mr: final round installed the child");

	IKEV2_CHILD_LIST_REMOVE(&sa->children, c);
	rc_vfree(c->addke_link);
	rc_vfreez(c->addke_sk);
	/* addke_priv was consumed by the driver (freed) on each round */
	free(c);
	free(sa);
	rc_vfree(pub0);
	rc_vfree(ct0);
	rc_vfree(ss0);
	rc_vfree(ct1);
}

/* H1 regression: a classical-DH ADDKE round must leave no dangling round
 * state behind.  ikev2_initiator_followup_complete() consumed the round's
 * DH keypair with rc_vfreez() but did not NULL addke_dh_pub/addke_dh_priv,
 * so child-SA teardown freed both a second time (double free / UAF) when
 * the last classical round was followed by ML-KEM rounds or by none.
 * Drive both shapes and then the real teardown helper under ASan. */
static void
initiator_classical_round_tests(void)
{
	const unsigned int m768 = IKEV2TRANSF_ADDKE_MLKEM768;
	struct ikev2_sa *sa;
	struct ikev2_child_sa *c;
	rc_vchar_t *pub = NULL, *peer = NULL;
	int shape;

	printf("--- IKE_FOLLOWUP_KE initiator classical-DH round (H1) ---\n");
	/* shape 2: final round with a failing child install -- the
	 * accumulated SK must be freed, not leaked (LeakSanitizer) */
	for (shape = 0; shape < 3; shape++) {
		sa = calloc(1, sizeof(*sa));
		c = calloc(1, sizeof(*c));
		if (!sa || !c) {
			free(sa); free(c);
			fail = 1;
			return;
		}
		IKEV2_CHILD_LIST_INIT(&sa->children);
		c->parent = sa;
		c->addke_pending = 1;
		c->addke_round = 0;
		c->addke_methods[0] = FAKE_DH_ID;
		/* shape 0: one classical round (last round classical);
		 * shape 1: classical round then an ML-KEM round */
		c->addke_nrounds = shape == 1 ? 2 : 1;
		c->addke_methods[1] = m768;
		c->addke_link = rc_vnew("clas", 4);
		IKEV2_CHILD_LIST_LINK(&sa->children, c);

		CHECK(ikev2_addke_round_keygen(c, FAKE_DH_ID, &pub) == 0 &&
		      pub && pub->l == FAKE_DH_PUBLEN,
		      "classical: round-0 keygen (KEi = DH public value)");
		CHECK(c->addke_dh != NULL && c->addke_dh_pub != NULL &&
		      c->addke_dh_priv != NULL && c->addke_method == FAKE_DH_ID,
		      "classical: round state stored");
		peer = rc_vmalloc(FAKE_DH_PUBLEN);
		memset(peer->v, 0x77, peer->l);

		n_child_install = 0;
		followup_reset();
		if (shape == 2) {
			child_install_fail = 1;
			CHECK(ikev2_initiator_followup_complete(c, peer) < 0,
			      "classical: failing install fails the round");
			child_install_fail = 0;
			CHECK(c->addke_sk == NULL && n_child_install == 1,
			      "classical: SK dropped on install failure (N2)");
		} else {
			CHECK(ikev2_initiator_followup_complete(c, peer) == 0,
			      "classical: complete round 0 (g^xy)");
			CHECK(c->addke_sk && c->addke_sk->l == FAKE_DH_SSLEN,
			      "classical: SK(1) is the group field length");
		}
		CHECK(c->addke_dh_pub == NULL && c->addke_dh_priv == NULL &&
		      c->addke_dh == NULL,
		      "classical: consumed round state is NULLed (H1)");
		if (shape == 2)
			;
		else if (shape == 0)
			CHECK(n_child_install == 1,
			      "classical: last (classical) round installs");
		else
			CHECK(n_child_install == 0 && c->addke_round == 1 &&
			      c->addke_priv != NULL && c->addke_method == m768,
			      "classical: ML-KEM round 1 armed after DH round 0");

		/* child-SA teardown path: must not touch the consumed DH
		 * round state again (ASan reports a double free if it does) */
		ikev2_addke_round_state_clear(c);
		CHECK(c->addke_priv == NULL && c->addke_dh_pub == NULL &&
		      c->addke_dh_priv == NULL,
		      "classical: teardown clears remaining round state");
		ikev2_addke_round_state_clear(c);	/* idempotent */

		IKEV2_CHILD_LIST_REMOVE(&sa->children, c);
		rc_vfree(c->addke_link);
		rc_vfreez(c->addke_sk);
		free(c);
		free(sa);
		rc_vfree(pub);
		rc_vfree(peer);
		pub = peer = NULL;
	}
}

/* M3: RFC 9370 s2.2.1/s2.2.2 round derivation from a selected proposal.
 * Build a proposal whose transforms are (type, id) pairs and check the
 * rounds ikev2_addke_collect_rounds() derives from it. */
#define CR_MAXT	10
static int
collect(const unsigned int (*tt)[2], int nt, unsigned int *methods,
	int *nrounds, int *offered)
{
	static struct ikev2transform tr[CR_MAXT];
	static struct prop_pair pp[CR_MAXT], head;
	int i;

	memset(&head, 0, sizeof(head));
	memset(pp, 0, sizeof(pp));
	memset(tr, 0, sizeof(tr));
	for (i = 0; i < nt && i < CR_MAXT; i++) {
		tr[i].transform_type = (uint8_t)tt[i][0];
		tr[i].transform_id = htons((uint16_t)tt[i][1]);
		pp[i].trns = (struct isakmp_pl_t *)&tr[i];
		pp[i].next = (i + 1 < nt) ? &pp[i + 1] : NULL;
	}
	head.tnext = nt ? &pp[0] : NULL;
	return ikev2_addke_collect_rounds(&head, methods, nrounds, offered);
}

static void
collect_rounds_tests(void)
{
	unsigned int m[IKEV2_ADDKE_MAX_ROUNDS];
	int n, off;

	printf("--- RFC 9370 round derivation (NONE, duplicates) ---\n");
	{	/* ENCR + ADDKE1=768, ADDKE2=NONE, ADDKE3=ECP256 */
		static const unsigned int t[][2] = {
			{ 1, 20 }, { 6, 36 }, { 7, 0 }, { 8, 19 } };
		CHECK(collect(t, 4, m, &n, &off) == 0 && off == 1 && n == 2 &&
		      m[0] == 36 && m[1] == 19,
		      "collect: NONE choice is skipped, not a round");
	}
	{	/* every ADDKE type NONE: standard IKEv2, zero rounds */
		static const unsigned int t[][2] = { { 6, 0 }, { 7, 0 } };
		CHECK(collect(t, 2, m, &n, &off) == 0 && off == 1 && n == 0,
		      "collect: all-NONE selection runs no rounds");
	}
	{	/* repeated method across types: MUST fail */
		static const unsigned int t[][2] = {
			{ 6, 36 }, { 7, 19 }, { 8, 36 } };
		CHECK(collect(t, 3, m, &n, &off) < 0,
		      "collect: duplicated method is rejected");
	}
	{	/* NONE twice is allowed (s2.2.2 "except for NONE") */
		static const unsigned int t[][2] = {
			{ 6, 0 }, { 7, 0 }, { 8, 35 } };
		CHECK(collect(t, 3, m, &n, &off) == 0 && n == 1 && m[0] == 35,
		      "collect: repeated NONE is not a duplicate");
	}
	{	/* wire order != type order; type 13 is not ADDKE */
		static const unsigned int t[][2] = {
			{ 12, 31 }, { 13, 37 }, { 6, 35 } };
		CHECK(collect(t, 3, m, &n, &off) == 0 && n == 2 &&
		      m[0] == 35 && m[1] == 31,
		      "collect: rounds in type order, ADDKE7 last, type 13 ignored");
	}
	{	/* no ADDKE transform at all */
		static const unsigned int t[][2] = { { 1, 20 }, { 4, 19 } };
		CHECK(collect(t, 2, m, &n, &off) == 0 && off == 0 && n == 0,
		      "collect: no ADDKE types -> not offered, zero rounds");
	}
}

int
main(void)
{
	/*
	 * Parameter sets under test: IKEv2 transform id, openssl CLI
	 * algorithm name, FIPS 203 public/ciphertext sizes.
	 */
	static const struct {
		unsigned int tid;
		const char *alg;
		size_t pub_len;
		size_t ct_len;
	} sets[] = {
		{ IKEV2TRANSF_ADDKE_MLKEM512, "ML-KEM-512",
		  OSSL_ML_KEM_512_PUBLIC_KEY_BYTES,
		  OSSL_ML_KEM_512_CIPHERTEXT_BYTES },
		{ IKEV2TRANSF_ADDKE_MLKEM768, "ML-KEM-768",
		  OSSL_ML_KEM_768_PUBLIC_KEY_BYTES,
		  OSSL_ML_KEM_768_CIPHERTEXT_BYTES },
		{ IKEV2TRANSF_ADDKE_MLKEM1024, "ML-KEM-1024",
		  OSSL_ML_KEM_1024_PUBLIC_KEY_BYTES,
		  OSSL_ML_KEM_1024_CIPHERTEXT_BYTES },
		{ 0, NULL, 0, 0 }
	};
	int have_cli = (access(prog, X_OK) == 0);
	size_t s;

	fail = 0;

	CHECK(ikev2_addke_selftest() == 0, "mlkem selftest (round-trip)");
	followup_link_tests();
	followup_multiround_tests();
	initiator_multiround_tests();
	initiator_classical_round_tests();
	collect_rounds_tests();

	if (have_cli) {
		for (s = 0; sets[s].alg != NULL; ++s) {
			rc_vchar_t *pub = NULL, *ct = NULL, *ss_ours = NULL;
			rc_vchar_t *cli_secret = NULL, *cli_ct = NULL;
			rc_vchar_t *ss_decap = NULL;
			EVP_PKEY *kp = NULL;
			char *pubfile = NULL, *secfile = NULL, *ctfile = NULL;
			unsigned char *der = NULL;
			int derlen;
			FILE *fs;
			int cli_ok;
			int set_fail = 0;

			printf("--- parameter set %s ---\n", sets[s].alg);
			CHECK(ikev2_addke_mlkem_keygen(sets[s].tid, &pub, &kp)
			      == 0, "keygen");
			if (pub == NULL || kp == NULL) {
				fail = 1;
				set_fail = 1;
				goto next_set;
			}

			/* CLI encapsulates against our public key */
			derlen = i2d_PUBKEY(kp, &der);
			pubfile = tmp_path("addke-pub", der, (size_t)derlen);
			OPENSSL_free(der);
			der = NULL;
			secfile = tmp_path("addke-sec", "", 0);
			ctfile = tmp_path("addke-ct", "", 0);
			CHECK(pubfile != NULL && secfile != NULL &&
			      ctfile != NULL, "tmpfiles");
			fs = fopen(secfile, "wb"); if (fs) fclose(fs);
			fs = fopen(ctfile, "wb"); if (fs) fclose(fs);

			cli_ok = (cli_encap(pubfile, secfile, ctfile) == 0);
			CHECK(cli_ok, "cli pkeyutl -encap");

			if (cli_ok) {
				cli_ct = read_file_rc(ctfile);
				cli_secret = read_file_rc(secfile);
				CHECK(cli_ct != NULL && cli_secret != NULL,
				      "read cli outputs");
				CHECK(cli_secret->l ==
				      OSSL_ML_KEM_SHARED_SECRET_BYTES,
				      "cli secret is 32 bytes");

				/* our decap must recover the CLI's secret */
				CHECK(ikev2_addke_mlkem_decap(kp, cli_ct,
							      &ss_decap) == 0,
				      "decap cli ciphertext");
				CHECK(ss_decap && cli_secret &&
				      ss_decap->l == cli_secret->l &&
				      memcmp(ss_decap->v, cli_secret->v,
					     cli_secret->l) == 0,
				      "shared secret matches cli");
			}

			/* our encap must be decap-able by the CLI -- the
			 * responder-direction pin: the CLI (as initiator)
			 * generates the keypair, our encap runs against
			 * its public key, the CLI decapsulates our
			 * ciphertext and must recover the same 32-byte
			 * secret (the IKE_FOLLOWUP_KE responder role). */
			{
				char *clipriv = NULL, *clipub = NULL;
				char *ourct = NULL, *clisec = NULL;
				rc_vchar_t *cli_pub = NULL, *our_ct = NULL;
				rc_vchar_t *our_ss = NULL, *cli_ss = NULL;
				int k_ok;

				clipriv = tmp_path("addke-clipriv", "", 0);
				clipub = tmp_path("addke-clipub", "", 0);
				ourct = tmp_path("addke-ourct", "", 0);
				clisec = tmp_path("addke-clisec", "", 0);
				CHECK(clipriv && clipub && ourct && clisec,
				      "tmpfiles (responder dir)");
				fs = fopen(clipriv, "wb"); if (fs) fclose(fs);
				fs = fopen(clipub, "wb"); if (fs) fclose(fs);
				fs = fopen(ourct, "wb"); if (fs) fclose(fs);
				fs = fopen(clisec, "wb"); if (fs) fclose(fs);

				k_ok = (cli_keygen(sets[s].alg, clipriv,
						   clipub) == 0);
				CHECK(k_ok, "cli genpkey");

				if (k_ok) {
					EVP_PKEY *cli_pkey = NULL;
					unsigned char rawpub[4096];
					size_t rawlen = sizeof(rawpub);
					const unsigned char *derp;
					FILE *pf;

					/* DER SPKI -> raw ML-KEM pubkey
					 * (what the KE payload carries) */
					pf = fopen(clipub, "rb");
					if (pf) {
						unsigned char buf[8192];
						size_t n = fread(buf, 1,
							 sizeof(buf), pf);
						fclose(pf);
						derp = buf;
						cli_pkey = d2i_PUBKEY(NULL,
								      &derp,
								      (long)n);
					}
					CHECK(cli_pkey != NULL,
					      "cli pubkey parses as SPKI");
					if (cli_pkey) {
						CHECK(EVP_PKEY_get_raw_public_key(
						    cli_pkey, rawpub,
						    &rawlen) > 0 &&
						    rawlen == sets[s].pub_len,
						    "cli raw pubkey size");
					}

					/* our encap against the CLI pubkey */
					cli_pub = rc_vnew(rawpub, rawlen);
					CHECK(cli_pub->l == sets[s].pub_len,
					      "cli pubkey size");
					CHECK(ikev2_addke_mlkem_encap(
						  sets[s].tid, cli_pub,
						  &our_ct, &our_ss) == 0,
					      "our encapsulate");
					CHECK(our_ct && our_ss &&
					      our_ct->l == sets[s].ct_len &&
					      our_ss->l ==
					      OSSL_ML_KEM_SHARED_SECRET_BYTES,
					      "our ct/ss sizes");

					/* CLI decapsulates our ciphertext */
					fs = fopen(ourct, "wb");
					if (fs) { fwrite(our_ct->v, 1,
							 our_ct->l, fs);
						 fclose(fs); }
					CHECK(cli_decap(clipriv, ourct,
							clisec) == 0,
					      "cli pkeyutl -decap");
					cli_ss = read_file_rc(clisec);
					CHECK(cli_ss != NULL &&
					      cli_ss->l == our_ss->l &&
					      memcmp(cli_ss->v, our_ss->v,
						     our_ss->l) == 0,
					      "responder-direction secret "
					      "matches cli");

					EVP_PKEY_free(cli_pkey);
				}

				if (clipriv) { unlink(clipriv); free(clipriv); }
				if (clipub) { unlink(clipub); free(clipub); }
				if (ourct) { unlink(ourct); free(ourct); }
				if (clisec) { unlink(clisec); free(clisec); }
				rc_vfree(cli_pub); rc_vfree(our_ct);
				rc_vfree(our_ss); rc_vfree(cli_ss);
			}

		      next_set:
			rc_vfree(pub);
			rc_vfree(ct);
			rc_vfree(ss_ours);
			rc_vfree(cli_secret);
			rc_vfree(cli_ct);
			rc_vfree(ss_decap);
			EVP_PKEY_free(kp);
			if (pubfile) { unlink(pubfile); free(pubfile); }
			if (secfile) { unlink(secfile); free(secfile); }
			if (ctfile) { unlink(ctfile); free(ctfile); }
			if (set_fail)
				break;
		}
	} else {
		printf("skip: openssl CLI unavailable (continuing)\n");
	}

	if (fail) {
		fprintf(stderr, "addketest: FAILURES\n");
		return 1;
	}
	printf("addketest: all checks passed\n");
	return 0;
}

#endif	/* WITH_ADDKE */
