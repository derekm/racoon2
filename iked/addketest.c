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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/ml_kem.h>
#include <openssl/x509.h>
#include <openssl/crypto.h>	/* OPENSSL_free */

#include "racoon.h"
#include "isakmp.h"
#include "isakmp_impl.h"
#include "ikev2.h"
#include "ikev2_impl.h"

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

void
isakmp_log(struct ikev2_sa *ike_sa, struct sockaddr *local,
	   struct sockaddr *remote, rc_vchar_t *msg, int query,
	   const char *loc, const char *fmt, ...)
{
	(void)ike_sa; (void)local; (void)remote; (void)msg;
	(void)query; (void)loc; (void)fmt;
}

int
ikev2_respond_error(struct ikev2_sa *ike_sa, rc_vchar_t *msg,
		    struct sockaddr *remote, struct sockaddr *local,
		    unsigned int a, uint8_t *b, int c, unsigned int d,
		    void *e, size_t f)
{
	(void)ike_sa; (void)msg; (void)remote; (void)local;
	(void)a; (void)b; (void)c; (void)d; (void)e; (void)f;
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
	(void)exch_type; (void)flags; (void)message_id;
	(void)sa; (void)payl;
	return NULL;
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
	(void)sa; (void)pkt; (void)local; (void)remote;
	return -1;
}

int
ikev2_transmit(struct ikev2_sa *sa, rc_vchar_t *pkt)
{
	(void)sa; (void)pkt;
	return -1;
}

void
ikev2_update_message_id(struct ikev2_sa *sa, uint32_t id, int is_response)
{
	(void)sa; (void)id; (void)is_response;
}

int
ikev2_child_addke_install(struct ikev2_child_sa *child_sa)
{
	(void)child_sa;
	return -1;
}

void
ikev2_child_addke_arm_timeout(struct ikev2_child_sa *child_sa)
{
	(void)child_sa;
}

int
ikev2_rekey_responder_addke_complete(struct ikev2_sa *sa, rc_vchar_t *sk,
				     rc_vchar_t *ct)
{
	(void)sa; (void)sk; (void)ct;
	return -1;
}

uint32_t
ikev2_rekey_ikesa_init_followup_msgid(struct ikev2_sa *sa)
{
	(void)sa;
	return 0;
}

int
ikev2_rekey_ikesa_init_addke_complete(struct ikev2_sa *sa, rc_vchar_t *ct)
{
	(void)sa; (void)ct;
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
