/* $Id: crypto_openssl.c,v 1.68 2010/02/01 10:30:51 fukumoto Exp $ */
/*	$KAME: crypto_openssl.c,v 1.83 2003/11/13 19:51:43 sakane Exp $	*/

/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <config.h>

#include <assert.h>
#include <sys/types.h>
#include <sys/param.h>
#if TIME_WITH_SYS_TIME
#  include <sys/time.h>
#  include <time.h>
#else
#  if HAVE_SYS_TIME_H
#    include <sys/time.h>
#  else
#    include <time.h>
#  endif
#endif

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <netinet/in.h>		/* for htonl() */

#include "racoon.h"

#include "var.h"
#include "crypto_impl.h"
#include "debug.h"
#include "gcmalloc.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/provider.h>
#include <openssl/crypto.h>
#endif
#ifdef WITH_OPENSSL_ENGINE
#include <openssl/engine.h>
#endif

static const char *eay_provider_name;
static const char *eay_engine_id;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
/*
 * Provider references taken by eay_init(), released by eay_cleanup().
 * OSSL_PROVIDER_load() takes a reference that must be dropped with
 * OSSL_PROVIDER_unload(); otherwise the provider's internal state is
 * never freed (seen as leaked CRYPTO_malloc blocks under LeakSanitizer).
 */
static OSSL_PROVIDER *eay_prov_default;
static OSSL_PROVIDER *eay_prov_extra;
static int eay_initialized;
#endif
#ifdef WITH_OPENSSL_ENGINE
static ENGINE *eay_engine;
#endif

void
eay_set_provider(const char *name)
{
	eay_provider_name = name;
}

void
eay_set_engine(const char *id)
{
	eay_engine_id = id;
}

void
eay_init(void)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	/* idempotent: eaytest (and re-entrant callers) may call twice */
	if (eay_initialized)
		return;
	eay_initialized = 1;
	OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);
	eay_prov_default = OSSL_PROVIDER_load(NULL, "default");
	if (eay_prov_default == NULL)
		plog(PLOG_INTWARN, PLOGLOC, NULL,
		    "OpenSSL default provider failed to load\n");
	if (eay_provider_name && *eay_provider_name) {
		eay_prov_extra = OSSL_PROVIDER_load(NULL, eay_provider_name);
		if (eay_prov_extra == NULL)
			plog(PLOG_INTERR, PLOGLOC, NULL,
			    "OpenSSL provider '%s' failed to load\n",
			    eay_provider_name);
		else
			plog(PLOG_INFO, PLOGLOC, NULL,
			    "OpenSSL provider '%s' loaded\n",
			    eay_provider_name);
	} else if (eay_engine_id && *eay_engine_id) {
		/* OpenSSL 3.x folded ENGINEs into the provider model;
		 * map the legacy RACOON2_OPENSSL_ENGINE knob onto
		 * provider loading so existing configs keep working
		 * (OpenSSL 3.5 removed <openssl/engine.h> entirely). */
		eay_prov_extra = OSSL_PROVIDER_load(NULL, eay_engine_id);
		if (eay_prov_extra == NULL)
			plog(PLOG_INTERR, PLOGLOC, NULL,
			    "OpenSSL provider '%s' (from engine setting) "
			    "failed to load\n", eay_engine_id);
		else
			plog(PLOG_INFO, PLOGLOC, NULL,
			    "OpenSSL provider '%s' (from engine setting) "
			    "loaded\n", eay_engine_id);
	}
#else
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
#endif
#ifdef WITH_OPENSSL_ENGINE
	ENGINE_load_builtin_engines();
	if (eay_engine_id && *eay_engine_id) {
		eay_engine = ENGINE_by_id(eay_engine_id);
		if (eay_engine == NULL || !ENGINE_init(eay_engine)) {
			plog(PLOG_INTERR, PLOGLOC, NULL,
			    "OpenSSL ENGINE '%s' failed\n", eay_engine_id);
			if (eay_engine) {
				ENGINE_free(eay_engine);
				eay_engine = NULL;
			}
		} else {
			if (!ENGINE_set_default(eay_engine, ENGINE_METHOD_ALL)) {
				plog(PLOG_INTERR, PLOGLOC, NULL,
				    "OpenSSL ENGINE '%s' set_default failed\n",
				    eay_engine_id);
				ENGINE_finish(eay_engine);
				ENGINE_free(eay_engine);
				eay_engine = NULL;
			} else
				plog(PLOG_INFO, PLOGLOC, NULL,
				    "OpenSSL ENGINE '%s' is default\n",
				    eay_engine_id);
		}
	} else {
		ENGINE_register_all_complete();
	}
#endif
}

void
eay_cleanup(void)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	/*
	 * Symmetric with eay_init(): drop the provider references we took so
	 * OpenSSL frees their internal state at shutdown (otherwise they
	 * leak -- visible as indirect CRYPTO_malloc leaks in eaytest under
	 * AddressSanitizer/LeakSanitizer).
	 */
	if (eay_prov_extra != NULL) {
		OSSL_PROVIDER_unload(eay_prov_extra);
		eay_prov_extra = NULL;
	}
	if (eay_prov_default != NULL) {
		OSSL_PROVIDER_unload(eay_prov_default);
		eay_prov_default = NULL;
	}
	eay_initialized = 0;
#endif
#ifdef WITH_OPENSSL_ENGINE
	if (eay_engine) {
		ENGINE_finish(eay_engine);
		ENGINE_free(eay_engine);
		eay_engine = NULL;
	}
	ENGINE_cleanup();
#endif
}

#ifdef HAVE_SIGNING_C
static int cb_check_cert(int, X509_STORE_CTX *);
static X509 *mem2x509(rc_vchar_t *);
#endif
static caddr_t eay_hmac_init(rc_vchar_t *, const EVP_MD *);

#ifdef HAVE_SIGNING_C

/*
 * internal to vmbuf conversion
 */
#define	IMPLEMENT_I2V(type_)	IMPLEMENT_I2V_name(type_, type_)

#define	IMPLEMENT_I2V_name(type_, name_)				\
	static rc_vchar_t * i2v_##name_(type_ *v)			\
	{								\
		rc_vchar_t	* buf;					\
		int	len;						\
		unsigned char	* bp;					\
									\
		len = i2d_##name_(v, NULL);				\
		if (len == 0) return 0;					\
		buf = rc_vmalloc(len);					\
		if (! buf) return 0;					\
		bp = (unsigned char *) buf->v;				\
		len = i2d_##name_(v, &bp);				\
		if (len == 0) {						\
			rc_vfree(buf);					\
			return 0;					\
		}							\
		return buf;						\
	}

IMPLEMENT_I2V(X509)
IMPLEMENT_I2V(X509_NAME)
IMPLEMENT_I2V_name(EVP_PKEY, PUBKEY)
IMPLEMENT_I2V_name(EVP_PKEY, PublicKey)
IMPLEMENT_I2V_name(EVP_PKEY, PrivateKey)
IMPLEMENT_I2V(PKCS12)


/* X509 Certificate */
/*
 * convert the string of the subject name into DER
 * e.g. str = "C=JP, ST=Kanagawa";
 */
rc_vchar_t *
eay_str2asn1dn(char *str, int len)
{
	X509_NAME *name;
	char *buf;
	char *field, *value;
	int i, j;
	rc_vchar_t *ret;

	buf = racoon_malloc(len + 1);
	if (!buf) {
#ifdef EAYDEBUG
		printf("failed to allocate buffer\n");
#endif
		return NULL;
	}
	memcpy(buf, str, len);

	name = X509_NAME_new();

	field = &buf[0];
	value = NULL;
	for (i = 0; i < len; i++) {
		if (!value && buf[i] == '=') {
			buf[i] = '\0';
			value = &buf[i + 1];
			continue;
		} else if (buf[i] == ',' || buf[i] == '/') {
			buf[i] = '\0';
#if 0
			printf("[%s][%s]\n", field, value);
#endif
			if (!X509_NAME_add_entry_by_txt(name, field,
			    MBSTRING_ASC, (unsigned char *)value, -1, -1, 0))
				goto err;
			for (j = i + 1; j < len; j++) {
				if (buf[j] != ' ')
					break;
			}
			field = &buf[j];
			value = NULL;
			continue;
		}
	}
	buf[len] = '\0';
#if 0
	printf("[%s][%s]\n", field, value);
#endif
	if (!X509_NAME_add_entry_by_txt(name, field,
	    MBSTRING_ASC, (unsigned char *)value, -1, -1, 0))
		goto err;

	ret = i2v_X509_NAME(name);
	X509_NAME_free(name);
	return ret;

      err:
	if (buf)
		racoon_free(buf);
	if (name)
		X509_NAME_free(name);
	return NULL;
}

/*
 * compare two subjectNames.
 * OUT:        0: equal
 *	positive:
 *	      -1: other error.
 */
int
eay_cmp_asn1dn(rc_vchar_t *n1, rc_vchar_t *n2)
{
	X509_NAME *a = NULL, *b = NULL;
	BPP_const unsigned char *p;
	int i = -1;

	p = (unsigned char *)n1->v;
	if (!d2i_X509_NAME(&a, &p, n1->l))
		goto end;
	p = (unsigned char *)n2->v;
	if (!d2i_X509_NAME(&b, &p, n2->l))
		goto end;

	i = X509_NAME_cmp(a, b);

      end:
	if (a)
		X509_NAME_free(a);
	if (b)
		X509_NAME_free(b);
	return i;
}

/*
 * this functions is derived from apps/verify.c in OpenSSL0.9.5
 */
int
eay_check_x509cert(rc_vchar_t *cert, char *CApath)
{
	X509_STORE *cert_ctx = NULL;
	X509_LOOKUP *lookup = NULL;
	X509 *x509 = NULL;
#if OPENSSL_VERSION_NUMBER >= 0x00905100L
	X509_STORE_CTX *csc;
#else
	X509_STORE_CTX csc;
#endif
	int error = -1;

	cert_ctx = X509_STORE_new();
	if (cert_ctx == NULL)
		goto end;
	X509_STORE_set_verify_cb_func(cert_ctx, cb_check_cert);

	if (!CApath)
		error = X509_STORE_set_default_paths(cert_ctx);
	else {
		X509_STORE_load_locations(cert_ctx, NULL, CApath);

		lookup = X509_STORE_add_lookup(cert_ctx, X509_LOOKUP_file());
		if (lookup == NULL)
			goto end;
		X509_LOOKUP_load_file(lookup, NULL, X509_FILETYPE_DEFAULT);	/* XXX */

		lookup = X509_STORE_add_lookup(cert_ctx,
					       X509_LOOKUP_hash_dir());
		if (lookup == NULL)
			goto end;
		error = X509_LOOKUP_add_dir(lookup, CApath, X509_FILETYPE_PEM);
	}
	if (!error) {
		error = -1;
		goto end;
	}
	error = -1;		/* initialized */

	/* read the certificate to be verified */
	x509 = mem2x509(cert);
	if (x509 == NULL)
		goto end;

#if OPENSSL_VERSION_NUMBER >= 0x00905100L
	csc = X509_STORE_CTX_new();
	if (csc == NULL)
		goto end;
	X509_STORE_CTX_init(csc, cert_ctx, x509, NULL);
	error = X509_verify_cert(csc);
	X509_STORE_CTX_cleanup(csc);
#else
	X509_STORE_CTX_init(&csc, cert_ctx, x509, NULL);
	error = X509_verify_cert(&csc);
	X509_STORE_CTX_cleanup(&csc);
#endif

	/*
	 * if x509_verify_cert() is successful then the value of error is
	 * set non-zero.
	 */
	error = error ? 0 : -1;

      end:
	if (error) {
#ifdef EAYDEBUG
		printf("%s\n", eay_strerror());
#else
		plog(PLOG_INTERR, PLOGLOC, 0,
		     "%s\n", eay_strerror());
#endif
	}
	if (cert_ctx != NULL)
		X509_STORE_free(cert_ctx);
	if (x509 != NULL)
		X509_free(x509);

	return (error);
}

/*
 * callback function for verifing certificate.
 * this function is derived from cb() in openssl/apps/s_server.c
 */
static int
cb_check_cert(int ok, X509_STORE_CTX *ctx)
{
	char buf[256];
	int log_tag;
	int ctx_error, ctx_error_depth;

	if (!ok) {
		X509_NAME_oneline(X509_get_subject_name(
		    X509_STORE_CTX_get0_cert(ctx)), buf, 256);
		/*
		 * since we are just checking the certificates, it is
		 * ok if they are self signed. But we should still warn
		 * the user.
		 */
		switch (ctx_error = X509_STORE_CTX_get_error(ctx)) {
		case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
#if OPENSSL_VERSION_NUMBER >= 0x00905100L
		case X509_V_ERR_INVALID_CA:
		case X509_V_ERR_PATH_LENGTH_EXCEEDED:
		case X509_V_ERR_INVALID_PURPOSE:
#endif
			ok = 1;
			log_tag = PLOG_PROTOWARN;
			break;
		case X509_V_ERR_CERT_HAS_EXPIRED:
		default:
			log_tag = PLOG_PROTOERR;
		}
		ctx_error_depth = X509_STORE_CTX_get_error_depth(ctx);
#ifndef EAYDEBUG
		plog(log_tag, PLOGLOC, NULL,
		     "%s(%d) at depth:%d SubjectName:%s\n",
		     X509_verify_cert_error_string(ctx_error),
		     ctx_error, ctx_error_depth, buf);
#else
		printf("%d: %s(%d) at depth:%d SubjectName:%s\n",
		       log_tag,
		       X509_verify_cert_error_string(ctx_error),
		       ctx_error, ctx_error_depth, buf);
#endif
	}
	ERR_clear_error();

	return ok;
}

/*
 * convert ASN1_TIME to timeval
 * XXX time_t may not be adequate
 */
#ifndef HAVE_TIMEGM
time_t
timegm(struct tm * tm)
{
	char *tz;
	time_t value;

	tz = getenv("TZ");
	putenv("TZ=");
	tzset();
	value = mktime(tm);
	if (tz)
		setenv("TZ", tz, 1);
	else
		unsetenv("TZ");
	tzset();
	return value;
}
#endif

static int
c2(unsigned char *s)
{
	return (s[0] - '0') * 10 + (s[1] - '0');
}

static int
eay_utctime(struct timeval *t, ASN1_TIME *u)
{
	int len;
	unsigned char *s;
	int i;
	struct tm tm;

	if (u->type != V_ASN1_UTCTIME)
		return -1;
	len = u->length;
	s = (unsigned char *)u->data;

	/*
	 * YYMMDDhhmmssZ
	 */
	/*
	 * Restriction by DER
	 * + encoding shall terminate with "Z"
	 * + seconds element shall always be present
	 */
	/* (RFC3280)
	 * 4.1.2.5.1  UTCTime
	 *
	 * The universal time type, UTCTime, is a standard ASN.1 type intended
	 * for representation of dates and time.  UTCTime specifies the year
	 * through the two low order digits and time is specified to the
	 * precision of one minute or one second.  UTCTime includes either Z
	 * (for Zulu, or Greenwich Mean Time) or a time differential.
	 *
	 * For the purposes of this profile, UTCTime values MUST be expressed
	 * Greenwich Mean Time (Zulu) and MUST include seconds (i.e., times are
	 * YYMMDDHHMMSSZ), even where the number of seconds is zero.  Conforming
	 * systems MUST interpret the year field (YY) as follows:
	 *
	 * Where YY is greater than or equal to 50, the year SHALL be
	 * interpreted as 19YY; and
	 *
	 * Where YY is less than 50, the year SHALL be interpreted as 20YY.
	 */

	if (len != 13)
		return -1;
	for (i = 0; i < 12; ++i)
		if (!isdigit(s[i]))
			return -1;
	if (s[12] != 'Z')
		return -1;

	tm.tm_year = c2(&s[0]);
	if (tm.tm_year < 50)
		tm.tm_year += 100;

	tm.tm_mon = c2(&s[2]) - 1;	/* 0..11 */
	tm.tm_mday = c2(&s[4]);
	tm.tm_hour = c2(&s[6]);
	tm.tm_min = c2(&s[8]);
	tm.tm_sec = c2(&s[10]);

	t->tv_sec = timegm(&tm);
	t->tv_usec = 0;
	return 0;
}

static int
eay_generalizedtime(struct timeval *t, ASN1_TIME *g)
{
	int len;
	unsigned char *s;
	int i;
	struct tm tm;

	if (g->type != V_ASN1_GENERALIZEDTIME)
		return -1;
	len = g->length;
	s = (unsigned char *)g->data;

	/*
	 * (a) implicit localtime
	 * "20050401235959.9"   year4+month2+day2+time(with comma or period)
	 *
	 * (b) UTC
	 * "20050401235959.9Z"  (a)+"Z"
	 *
	 * (c) explicit localtime
	 * "20050401235959.9+0900"      (a)+timezone difference
	 */
	/*
	 * Restriction by DER
	 * - encoding shall terminate with a "Z"
	 * - seconds element shall always be present
	 * - fractional-seconds elements, if present, shall omit all trailing zeros;
	 * - decimal point element, if present, shall be the point option ","
	 * (XXX this doesn't match with OpenSSL)
	 */
	/* (RFC3280)
	 * 4.1.2.5.2  GeneralizedTime
	 *
	 * The generalized time type, GeneralizedTime, is a standard ASN.1 type
	 * for variable precision representation of time.  Optionally, the
	 * GeneralizedTime field can include a representation of the time
	 * differential between local and Greenwich Mean Time.
	 *
	 * For the purposes of this profile, GeneralizedTime values MUST be
	 * expressed Greenwich Mean Time (Zulu) and MUST include seconds (i.e.,
	 * times are YYYYMMDDHHMMSSZ), even where the number of seconds is zero.
	 * GeneralizedTime values MUST NOT include fractional seconds.
	 */

	if (len != 15)
		return -1;
	for (i = 0; i < 14; ++i)
		if (!isdigit(s[i]))
			return -1;
	if (s[14] != 'Z')
		return -1;

	tm.tm_year = (c2(&s[0]) * 100 + c2(&s[2])) - 1900;
	tm.tm_mon = c2(&s[4]) - 1;
	tm.tm_mday = c2(&s[6]);
	tm.tm_hour = c2(&s[8]);
	tm.tm_min = c2(&s[10]);
	tm.tm_sec = c2(&s[12]);

	t->tv_sec = timegm(&tm);
	t->tv_usec = 0;
	return 0;
}

static int
eay_time(struct timeval *t, ASN1_TIME *s)
{
	if (!s)
		return -1;

	switch (s->type) {
	case V_ASN1_UTCTIME:
		return eay_utctime(t, s);
		break;
	case V_ASN1_GENERALIZEDTIME:
		return eay_generalizedtime(t, s);
	default:
		return -1;
	}
}

/*
 * extract pubkey (asn1) from x509 cert (asn1)
 */
rc_vchar_t *
eay_get_x509_pubkey(rc_vchar_t *cert, struct timeval *due_time)
{
	EVP_PKEY *evp = NULL;
	rc_vchar_t *pkey = NULL;
	X509 *x509 = NULL;

	x509 = mem2x509(cert);
	if (x509 == NULL)
		return NULL;

	/* Get public key - eay */
	evp = X509_get_pubkey(x509);
	if (evp == NULL)
		return NULL;

	pkey = i2v_PUBKEY(evp);
	if (due_time) {
		if (eay_time(due_time, X509_get_notAfter(x509)) != 0) {
			EVP_PKEY_free(evp);
			return NULL;
		}

		/* *due_time = ASN1_UTCTIME_get(X509_get_notAfter(pkey)); */
	}
	EVP_PKEY_free(evp);
	return pkey;
}

/*
 * get a subjectName from X509 certificate.
 */
rc_vchar_t *
eay_get_x509asn1subjectname(rc_vchar_t *cert)
{
	X509 *x509 = NULL;
	rc_vchar_t *name = NULL;
	int error = -1;

	x509 = mem2x509(cert);
	if (x509 == NULL)
		goto end;

	name = i2v_X509_NAME(X509_get_subject_name(x509));
	error = 0;
      end:
	if (error) {
#ifndef EAYDEBUG
		plog(PLOG_PROTOERR, PLOGLOC, NULL, "%s\n", eay_strerror());
#else
		printf("%s\n", eay_strerror());
#endif
		if (name) {
			rc_vfree(name);
			name = NULL;
		}
	}
	if (x509)
		X509_free(x509);

	return name;
}

/*
 * get the subjectAltName from X509 certificate.
 * the name must be terminated by '\0'.
 */
int
eay_get_x509subjectaltname(rc_vchar_t *cert, char **altname, int *type, int pos)
{
	X509 *x509 = NULL;
	GENERAL_NAMES *gens;
	GENERAL_NAME *gen;
	int i, len;
	int error = -1;

	*altname = NULL;
	*type = GENT_OTHERNAME;

	x509 = mem2x509(cert);
	if (x509 == NULL)
		goto end;

	gens = X509_get_ext_d2i(x509, NID_subject_alt_name, NULL, NULL);
	if (gens == NULL)
		goto end;

	for (i = 0; i < sk_GENERAL_NAME_num(gens); i++) {
		if (i + 1 != pos)
			continue;
		break;
	}

	/* there is no data at "pos" */
	if (i == sk_GENERAL_NAME_num(gens))
		goto end;

	gen = sk_GENERAL_NAME_value(gens, i);

	/* make sure if the data is terminated by '\0'. */
	if (gen->d.ia5->data[gen->d.ia5->length] != '\0') {
#ifndef EAYDEBUG
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
		     "data is not terminated by '\\0'.\n");
		plogdump(PLOG_PROTOERR, PLOGLOC, 0,
			 gen->d.ia5->data, gen->d.ia5->length + 1);
#else
		hexdump(gen->d.ia5->data, gen->d.ia5->length + 1);
#endif
		goto end;
	}

	len = gen->d.ia5->length + 1;
	*altname = racoon_malloc(len);
	if (!*altname)
		goto end;

	strlcpy(*altname, (char *)gen->d.ia5->data, len);
	*type = gen->type;

	error = 0;

      end:
	if (error) {
		if (*altname) {
			racoon_free(*altname);
			*altname = NULL;
		}
#ifndef EAYDEBUG
		plog(PLOG_PROTOERR, PLOGLOC, NULL, "%s\n", eay_strerror());
#else
		printf("%s\n", eay_strerror());
#endif
	}
	if (x509)
		X509_free(x509);

	return error;
}

/*
 * decode a X509 certificate and make a readable text terminated '\n'.
 * return the buffer allocated, so must free it later.
 */
char *
eay_get_x509text(rc_vchar_t *cert)
{
	X509 *x509 = NULL;
	BIO *bio = NULL;
	char *text = NULL;
	unsigned char *bp = NULL;
	int len = 0;
	int error = -1;

	x509 = mem2x509(cert);
	if (x509 == NULL)
		goto end;

	bio = BIO_new(BIO_s_mem());
	if (bio == NULL)
		goto end;

	error = X509_print(bio, x509);
	if (error != 1) {
		error = -1;
		goto end;
	}

	len = BIO_get_mem_data(bio, &bp);
	text = racoon_malloc(len + 1);
	if (text == NULL)
		goto end;
	memcpy(text, bp, len);
	text[len] = '\0';

	error = 0;

      end:
	if (error) {
		if (text) {
			racoon_free(text);
			text = NULL;
		}
#ifndef EAYDEBUG
		plog(PLOG_PROTOERR, PLOGLOC, NULL, "%s\n", eay_strerror());
#else
		printf("%s\n", eay_strerror());
#endif
	}
	if (bio)
		BIO_free(bio);
	if (x509)
		X509_free(x509);

	return text;
}

/* get X509 structure from buffer. */
static X509 *
mem2x509(rc_vchar_t *cert)
{
	X509 *x509;

#ifndef EAYDEBUG
	{
		BPP_const unsigned char *bp;

		bp = (unsigned char *)cert->v;
		x509 = d2i_X509(NULL, &bp, cert->l);
	}
#else
	{
		BIO *bio;
		int len;

		bio = BIO_new(BIO_s_mem());
		if (bio == NULL)
			return NULL;
		len = BIO_write(bio, cert->v, cert->l);
		if (len == -1)
			return NULL;
		x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
		BIO_free(bio);
	}
#endif
	return x509;
}

/*
 * get a X509 certificate from local file.
 * a certificate must be PEM format.
 * Input:
 *	path to a certificate.
 * Output:
 *	NULL if error occured
 *	other is the cert.
 */
rc_vchar_t *
eay_get_x509cert(const char *path)
{
	FILE *fp;
	X509 *x509;
	rc_vchar_t *cert;

	/* Read private key */
	fp = fopen(path, "r");
	if (fp == NULL)
		return NULL;
#if OPENSSL_VERSION_NUMBER >= 0x00904100L
	x509 = PEM_read_X509(fp, NULL, NULL, NULL);
#else
	x509 = PEM_read_X509(fp, NULL, NULL);
#endif
	fclose(fp);

	if (x509 == NULL)
		return NULL;

	cert = i2v_X509(x509);
	X509_free(x509);
	return cert;
}

/*
 * sign a souce by X509 signature.
 * XXX: to be get hash type from my cert ?
 *	to be handled EVP_dss().
 */
/*ARGSUSED*/
rc_vchar_t *
eay_get_x509sign(rc_vchar_t *source, rc_vchar_t *privkey, rc_vchar_t *cert)
{
	rc_vchar_t *sig = NULL;

	sig = eay_rsa_sign(source, privkey);

	return sig;
}

/*
 * check a X509 signature
 *	XXX: to be get hash type from my cert ?
 *		to be handled EVP_dss().
 * OUT: return -1 when error.
 *	0
 */
int
eay_check_x509sign(rc_vchar_t *source, rc_vchar_t *sig, rc_vchar_t *cert)
{
	int retval;
	rc_vchar_t *pubkey;

	pubkey = eay_get_x509_pubkey(cert, 0);
	if (! pubkey)
		return -1;
	retval = eay_rsa_verify(source, sig, pubkey);
	rc_vfree(pubkey);
	return retval;
}

/*
 * get PKCS#1 Private Key of PEM format from local file.
 */
rc_vchar_t *
eay_get_pkcs1privkey(const char *path)
{
	FILE *fp;
	EVP_PKEY *evp = NULL;
	rc_vchar_t *pkey = NULL;

	/* Read private key */
	fp = fopen(path, "r");
	if (fp == NULL)
		return NULL;

#if OPENSSL_VERSION_NUMBER >= 0x00904100L
	evp = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
#else
	evp = PEM_read_PrivateKey(fp, NULL, NULL);
#endif
	fclose(fp);

	if (evp == NULL)
		return NULL;

	pkey = i2v_PrivateKey(evp);
	EVP_PKEY_free(evp);
	return pkey;
}

/*
 * get PKCS#1 Public Key of PEM format from local file.
 */
rc_vchar_t *
eay_get_pkcs1pubkey(const char *path)
{
	FILE *fp;
	EVP_PKEY *evp = NULL;
	rc_vchar_t *pkey = NULL;
	X509 *x509 = NULL;

	/* Read private key */
	fp = fopen(path, "r");
	if (fp == NULL)
		return NULL;

#if OPENSSL_VERSION_NUMBER >= 0x00904100L
	x509 = PEM_read_X509(fp, NULL, NULL, NULL);
#else
	x509 = PEM_read_X509(fp, NULL, NULL);
#endif
	fclose(fp);

	if (x509 == NULL)
		return NULL;

	/* Get public key - eay */
	evp = X509_get_pubkey(x509);
	if (evp == NULL)
		return NULL;

	pkey = i2v_PublicKey(evp);
	EVP_PKEY_free(evp);
	return pkey;
}

/*
 * read PKCS12 file (check syntax), then return vmbuf
 */
rc_vchar_t *
eay_get_pkcs12(const char *path)
{
	FILE *fp = 0;
	PKCS12 *p12 = 0;
	rc_vchar_t *buf = 0;

	fp = fopen(path, "r");
	if (fp == NULL)
		goto end;

	p12 = d2i_PKCS12_fp(fp, NULL);
	if (!p12)
		goto end;

	buf = i2v_PKCS12(p12);
      end:
	if (fp)
		fclose(fp);
	if (p12)
		PKCS12_free(p12);
	return buf;
}

/*
 * extract x509cert from PKCS12 (in vmbuf)
 */
rc_vchar_t *
eay_get_pkcs12_x509cert(rc_vchar_t *pk12, const char *passphrase)
{
	BPP_const unsigned char *bp;
	int success;
	PKCS12 *p12;
	X509 *x509;
	rc_vchar_t *cert = 0;

	bp = (unsigned char *)pk12->v;
	p12 = d2i_PKCS12(NULL, &bp, pk12->l);
	success = PKCS12_parse(p12, passphrase, NULL, &x509, NULL);
	PKCS12_free(p12);
	if (!success)
		return 0;
	cert = i2v_X509(x509);
	X509_free(x509);
	return cert;
}

/*
 * extract private key from PKCS12 (in vmbuf)
 */
rc_vchar_t *
eay_get_pkcs12_privkey(rc_vchar_t *pk12, const char *passphrase)
{
	BPP_const unsigned char *bp;
	int success;
	PKCS12 *p12;
	EVP_PKEY *privkey;
	rc_vchar_t *buf = 0;

	bp = (unsigned char *)pk12->v;
	p12 = d2i_PKCS12(NULL, &bp, pk12->l);
	success = PKCS12_parse(p12, passphrase, &privkey, NULL, NULL);
	PKCS12_free(p12);
	if (!success)
		return 0;

	buf = i2v_PrivateKey(privkey);
	EVP_PKEY_free(privkey);
	return buf;
}
#endif

rc_vchar_t *
eay_rsa_sign(rc_vchar_t *src, rc_vchar_t *privkey)
{
	EVP_PKEY *evp;
	BPP_const unsigned char *bp;
	rc_vchar_t *sig = NULL;
	int len;
	RSA *rsa;
	int pad = RSA_PKCS1_PADDING;

	bp = (unsigned char *)privkey->v;
	/* XXX to be handled EVP_PKEY_DSA */
	evp = d2i_PrivateKey(EVP_PKEY_RSA, NULL, &bp, privkey->l);
	if (evp == NULL)
		return NULL;

	/* XXX: to be handled EVP_dss() */
	/* XXX: Where can I get such parameters ?  From my cert ? */

	rsa = EVP_PKEY_get0_RSA(evp);
	len = RSA_size(rsa);

	sig = rc_vmalloc(len);
	if (sig == NULL)
		return NULL;

	len = RSA_private_encrypt(src->l, (unsigned char *)src->v,
				  (unsigned char *)sig->v, rsa, pad);
	EVP_PKEY_free(evp);
	if (len == 0 || (size_t)len != sig->l) {
		rc_vfree(sig);
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "%s\n", eay_strerror());
		sig = NULL;
	}

	return sig;
}

int
eay_rsa_verify(rc_vchar_t *src, rc_vchar_t *sig, rc_vchar_t *pubkey)
{
	EVP_PKEY *evp;
	BPP_const unsigned char *bp;
	rc_vchar_t *xbuf = NULL;
	int pad = RSA_PKCS1_PADDING;
	RSA *rsa;
	int len = 0;
	int error;

	bp = (unsigned char *)pubkey->v;
	evp = d2i_PUBKEY(NULL, &bp, pubkey->l);
	if (evp == NULL) {
#ifndef EAYDEBUG
		plog(PLOG_INTERR, PLOGLOC, NULL, "%s\n", eay_strerror());
#endif
		return -1;
	}

	rsa = EVP_PKEY_get0_RSA(evp);
	len = RSA_size(rsa);

	xbuf = rc_vmalloc(len);
	if (xbuf == NULL) {
#ifndef EAYDEBUG
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
		     "failed allocating memory\n");
#endif
		EVP_PKEY_free(evp);
		return -1;
	}

	len = RSA_public_decrypt(sig->l, (unsigned char *)sig->v,
				 (unsigned char *)xbuf->v, rsa, pad);
#ifndef EAYDEBUG
	if (len == 0 || (size_t)len != src->l)
		plog(PLOG_PROTOERR, PLOGLOC, NULL, "%s\n", eay_strerror());
#endif
	EVP_PKEY_free(evp);
	if (len == 0 || (size_t)len != src->l) {
		rc_vfree(xbuf);
		return -1;
	}

	error = memcmp(src->v, xbuf->v, src->l);
	rc_vfree(xbuf);
	if (error != 0)
		return -1;

	return 0;
}

/* (RFC2437) */
/*
 * calculate RSA_sign(Hash(octets), privkey) and return vmbuf
 *
 * hash_type:  name string of Hash
 * octets:     message to sign
 * privkey:    vmbuf of private key in PKCS#1 format
 */
rc_vchar_t *
eay_rsassa_pkcs1_v1_5_sign(const char *hash_type, rc_vchar_t *octets, rc_vchar_t *privkey)
{
	EVP_PKEY *pkey;
	BPP_const unsigned char *bp;
	int len;
	rc_vchar_t *sig = 0;
	unsigned int siglen;
	const EVP_MD *md;
	EVP_MD_CTX *ctx = NULL;
	RSA *rsa;

	bp = (unsigned char *)privkey->v;
	/* convert private key from vmbuf to internal data */
	pkey = d2i_PrivateKey(EVP_PKEY_RSA, NULL, &bp, privkey->l);
	if (pkey == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "failed obtaining private key: %s\n", eay_strerror());
		goto fail;
	}

	rsa = EVP_PKEY_get0_RSA(pkey);
	len = RSA_size(rsa);
	sig = rc_vmalloc(len);
	if (sig == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL, "failed allocating memory\n");
		goto fail;
	}

	/* RSA sign with private key */
	md = EVP_get_digestbyname(hash_type);
	if (!md) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "failed to find digest algorithm %s\n", hash_type);
		goto fail;
	}
	ctx = EVP_MD_CTX_new();
	if (!ctx) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "failed to allocate context\n");
		goto fail;
	}
	EVP_SignInit(ctx, md);
	EVP_SignUpdate(ctx, octets->v, octets->l);
	if (EVP_SignFinal(ctx, (unsigned char *)sig->v, &siglen, pkey) <= 0) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "RSA_sign failed: %s\n", eay_strerror());
		goto fail;
	}
	if (sig->l != siglen) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "unexpected signature length %d\n", siglen);
		goto fail;
	}
	EVP_MD_CTX_free(ctx);
	EVP_PKEY_free(pkey);
	return sig;

      fail:
	if (sig)
		rc_vfree(sig);
	if (ctx)
		EVP_MD_CTX_free(ctx);
	if (pkey)
		EVP_PKEY_free(pkey);
	return 0;
}

/*
 * hash_type:	name string of Hash function
 * octets:	message octets
 * sig: 	received signature data
 * pubkey:	vmbuf of public key in PKCS#1 format
 *
 * returns 0 if successful, non-0 otherwise
 */
int
eay_rsassa_pkcs1_v1_5_verify(const char *hash_type, rc_vchar_t *octets, rc_vchar_t *sig, rc_vchar_t *pubkey)
{
	EVP_PKEY *pkey;
	BPP_const unsigned char *bp;
	const EVP_MD *md;
	EVP_MD_CTX *ctx = NULL;

	bp = (unsigned char *)pubkey->v;
	pkey = d2i_PUBKEY(NULL, &bp, pubkey->l);
	if (pkey == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "failed obtaining public key: %s\n", eay_strerror());
		goto fail;
	}
	if (EVP_PKEY_id(pkey) != EVP_PKEY_RSA) {
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
		     "public key is not for RSA\n");
		goto fail;
	}

	md = EVP_get_digestbyname(hash_type);
	if (!md) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "failed to find the algorithm engine for %s\n", hash_type);
		goto fail;
	}
	ctx = EVP_MD_CTX_new();
	if (!ctx) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "failed to allocate context\n");
		goto fail;
	}
	EVP_VerifyInit(ctx, md);
	EVP_VerifyUpdate(ctx, octets->v, octets->l);
	if (EVP_VerifyFinal(ctx, (unsigned char *)sig->v, sig->l, pkey) <= 0) {
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
		     "RSA_verify failed: %s\n", eay_strerror());
		goto fail;
	}

	EVP_MD_CTX_free(ctx);
	EVP_PKEY_free(pkey);
	return 0;

      fail:
	if (pkey)
		EVP_PKEY_free(pkey);
	if (ctx)
		EVP_MD_CTX_free(ctx);
	return -1;
}

/*
 * generates a DSS signature over SHA1 hash of octets
 */
rc_vchar_t *
eay_dss_sign(rc_vchar_t *octets, rc_vchar_t *privkey)
{
	EVP_PKEY *pkey;
	BPP_const unsigned char *bp;
	const EVP_MD *md;
	EVP_MD_CTX *ctx = NULL;
	DSA *dsa;
	int len;
	rc_vchar_t *sig = 0;
	unsigned int siglen;

	bp = (unsigned char *)privkey->v;
	pkey = d2i_PrivateKey(EVP_PKEY_DSA3, NULL, &bp, privkey->l);
	if (pkey == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "failed obtaining private key: %s\n", eay_strerror());
		goto fail;
	}

	dsa = EVP_PKEY_get0_DSA(pkey);
	len = DSA_size(dsa);
	sig = rc_vmalloc(len);
	if (sig == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL, "failed allocating memory\n");
		goto fail;
	}

#if 0
	md = EVP_dss1();
#else
	md = NULL;
	goto fail;
#endif
	ctx = EVP_MD_CTX_new();
	if (!ctx) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "failed to allocate context\n");
		goto fail;
	}
	EVP_SignInit(ctx, md);
	EVP_SignUpdate(ctx, octets->v, octets->l);
	if (EVP_SignFinal(ctx, (unsigned char *)sig->v, &siglen, pkey) <= 0) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "DSS sign failed: %s\n", eay_strerror());
		goto fail;
	}

	if (siglen > sig->l) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "unexpected signature length (%u > %lu)\n",
		     siglen, (unsigned long)sig->l);
		goto fail;
	}
	if (siglen < sig->l)
		sig = rc_vrealloc(sig, siglen);
	EVP_PKEY_free(pkey);
	EVP_MD_CTX_free(ctx);
	return sig;

      fail:
	if (sig)
		rc_vfree(sig);
	if (pkey)
		EVP_PKEY_free(pkey);
	if (ctx)
		EVP_MD_CTX_free(ctx);
	return 0;
}

/*
 * verifies DSS signature
 * returns 0 if successfully verified, non-0 otherwise
 */
int
eay_dss_verify(rc_vchar_t *octets, rc_vchar_t *sig, rc_vchar_t *pubkey)
{
	EVP_PKEY *pkey;
	BPP_const unsigned char *bp;
	const EVP_MD *md;
	EVP_MD_CTX *ctx = NULL;

	bp = (unsigned char *)pubkey->v;
	pkey = d2i_PUBKEY(NULL, &bp, pubkey->l);
	if (pkey == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "failed obtaining public key: %s\n", eay_strerror());
		goto fail;
	}
	if (EVP_PKEY_id(pkey) != EVP_PKEY_DSA) {
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
		     "public key is not for DSS\n");
		goto fail;
	}

#if 0
	md = EVP_dss1();
#else
	md = NULL;
	goto fail;
#endif
	ctx = EVP_MD_CTX_new();
	if (!ctx) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "failed to allocate context\n");
		goto fail;
	}
	EVP_VerifyInit(ctx, md);
	EVP_VerifyUpdate(ctx, octets->v, octets->l);
	if (EVP_VerifyFinal(ctx, (unsigned char *)sig->v, sig->l, pkey) <= 0) {
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
		     "DSS verify failed: %s\n", eay_strerror());
		goto fail;
	}
	EVP_MD_CTX_free(ctx);
	EVP_PKEY_free(pkey);
	return 0;

      fail:
	if (pkey)
		EVP_PKEY_free(pkey);
	if (ctx)
		EVP_MD_CTX_free(ctx);
	return -1;
}

/* (RFC4754) */
/*
 * generates an ECDSA signature over Hash(octets) and returns the RAW
 * r || s octet string, NOT the DER-encoded ECDSA_SIG that EVP emits.
 * r and s are each exactly the size of the curve order (P-256: 32,
 * P-384: 48, P-521: 66 octets).
 *
 * hash_type:  name string of Hash function
 * octets:     message octets to sign
 * privkey:    vmbuf of private key in DER (SEC1 ECPrivateKey or PKCS#8)
 */
rc_vchar_t *
eay_ecdsa_sign(const char *hash_type, rc_vchar_t *octets,
	       rc_vchar_t *privkey)
{
	EVP_PKEY *pkey;
	BPP_const unsigned char *bp;
	const EVP_MD *md;
	EVP_MD_CTX *ctx = NULL;
	unsigned char *der = NULL;
	size_t derlen;
	const unsigned char *derp;
	ECDSA_SIG *esig = NULL;
	const BIGNUM *r, *s;
	rc_vchar_t *sig = 0;
	int width;

	bp = (unsigned char *)privkey->v;
	/* convert private key from vmbuf to internal data */
	pkey = d2i_AutoPrivateKey(NULL, &bp, privkey->l);
	if (pkey == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "failed obtaining private key: %s\n", eay_strerror());
		goto fail;
	}
	if (EVP_PKEY_id(pkey) != EVP_PKEY_EC) {
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
		     "private key is not an EC key\n");
		goto fail;
	}
	width = (EVP_PKEY_bits(pkey) + 7) / 8;
	if (width < 32) {
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
		     "unsupported ECDSA curve (%d bits)\n",
		     EVP_PKEY_bits(pkey));
		goto fail;
	}

	md = EVP_get_digestbyname(hash_type);
	if (!md) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "failed to find digest algorithm %s\n", hash_type);
		goto fail;
	}
	ctx = EVP_MD_CTX_new();
	if (!ctx) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "failed allocating context\n");
		goto fail;
	}
	if (EVP_DigestSignInit(ctx, NULL, md, NULL, pkey) != 1 ||
	    EVP_DigestSignUpdate(ctx, octets->v, octets->l) != 1 ||
	    EVP_DigestSignFinal(ctx, NULL, &derlen) != 1) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "ECDSA sign failed: %s\n", eay_strerror());
		goto fail;
	}
	der = malloc(derlen);
	if (der == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "failed allocating memory\n");
		goto fail;
	}
	if (EVP_DigestSignFinal(ctx, der, &derlen) != 1) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "ECDSA sign failed: %s\n", eay_strerror());
		goto fail;
	}

	/* convert the DER-encoded ECDSA_SIG to the raw r||s octet string */
	derp = der;
	esig = d2i_ECDSA_SIG(NULL, &derp, derlen);
	if (esig == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "failed parsing ECDSA signature: %s\n", eay_strerror());
		goto fail;
	}
	sig = rc_vmalloc(width * 2);
	if (sig == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "failed allocating memory\n");
		goto fail;
	}
	ECDSA_SIG_get0(esig, &r, &s);
	if (BN_bn2binpad(r, (unsigned char *)sig->v, width) != width ||
	    BN_bn2binpad(s, (unsigned char *)sig->v + width, width) != width) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "failed serializing ECDSA signature\n");
		goto fail;
	}
	EVP_MD_CTX_free(ctx);
	EVP_PKEY_free(pkey);
	ECDSA_SIG_free(esig);
	free(der);
	return sig;

      fail:
	if (sig)
		rc_vfree(sig);
	if (ctx)
		EVP_MD_CTX_free(ctx);
	if (pkey)
		EVP_PKEY_free(pkey);
	if (esig)
		ECDSA_SIG_free(esig);
	if (der)
		free(der);
	return 0;
}

/*
 * verifies the raw r||s ECDSA signature (RFC4754) over Hash(octets)
 * returns 0 if successfully verified, non-0 otherwise
 */
int
eay_ecdsa_verify(const char *hash_type, rc_vchar_t *octets, rc_vchar_t *sig,
		 rc_vchar_t *pubkey)
{
	EVP_PKEY *pkey;
	BPP_const unsigned char *bp;
	const EVP_MD *md;
	EVP_MD_CTX *ctx = NULL;
	unsigned char *der = NULL;
	int derlen;
	unsigned char *derout;
	ECDSA_SIG *esig = NULL;
	BIGNUM *r = NULL, *s = NULL;
	int width;

	bp = (unsigned char *)pubkey->v;
	pkey = d2i_PUBKEY(NULL, &bp, pubkey->l);
	if (pkey == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "failed obtaining public key: %s\n", eay_strerror());
		goto fail;
	}
	if (EVP_PKEY_id(pkey) != EVP_PKEY_EC) {
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
		     "public key is not an EC key\n");
		goto fail;
	}
	width = (EVP_PKEY_bits(pkey) + 7) / 8;
	if (sig->l != (size_t)(width * 2)) {
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
		     "invalid ECDSA signature length (%lu)\n",
		     (unsigned long)sig->l);
		goto fail;
	}

	/* convert the raw r||s octet string to a DER-encoded ECDSA_SIG */
	esig = ECDSA_SIG_new();
	if (esig == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "failed allocating ECDSA_SIG\n");
		goto fail;
	}
	r = BN_bin2bn((unsigned char *)sig->v, width, NULL);
	s = BN_bin2bn((unsigned char *)sig->v + width, width, NULL);
	if (r == NULL || s == NULL ||
	    ECDSA_SIG_set0(esig, r, s) != 1) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "failed parsing ECDSA signature: %s\n", eay_strerror());
		goto fail;
	}
	r = s = NULL;	/* esig owns them now */
	derlen = i2d_ECDSA_SIG(esig, NULL);
	if (derlen <= 0) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "failed encoding ECDSA signature: %s\n", eay_strerror());
		goto fail;
	}
	der = malloc(derlen);
	if (der == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "failed allocating memory\n");
		goto fail;
	}
	derout = der;
	if (i2d_ECDSA_SIG(esig, &derout) != derlen) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "failed encoding ECDSA signature\n");
		goto fail;
	}

	md = EVP_get_digestbyname(hash_type);
	if (!md) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "failed to find the digest algorithm %s\n", hash_type);
		goto fail;
	}
	ctx = EVP_MD_CTX_new();
	if (ctx == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "failed allocating context\n");
		goto fail;
	}
	if (EVP_DigestVerifyInit(ctx, NULL, md, NULL, pkey) != 1 ||
	    EVP_DigestVerifyUpdate(ctx, octets->v, octets->l) != 1 ||
	    EVP_DigestVerifyFinal(ctx, der, derlen) != 1) {
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
		     "ECDSA verify failed: %s\n", eay_strerror());
		goto fail;
	}

	EVP_MD_CTX_free(ctx);
	EVP_PKEY_free(pkey);
	ECDSA_SIG_free(esig);
	free(der);
	return 0;

      fail:
	if (r)
		BN_free(r);
	if (s)
		BN_free(s);
	if (ctx)
		EVP_MD_CTX_free(ctx);
	if (pkey)
		EVP_PKEY_free(pkey);
	if (esig)
		ECDSA_SIG_free(esig);
	if (der)
		free(der);
	return -1;
}

/*
 * returns the bit size of the EC group order of the private key
 * (256/384/521), 0 if the key is not an EC key or on error
 */
/*
 * RFC 7427 s3: verify the signature of a Digital Signature (AUTH method
 * 14) payload.  `ai' is the DER AlgorithmIdentifier the peer sent, `sig'
 * the signature value after it.  Accepted (RFC 8247 s3.2, RFC 7427
 * App. A):
 *   sha256/384/512WithRSAEncryption       RSASSA-PKCS1-v1_5
 *   id-RSASSA-PSS                         SHA-256/384/512, MGF1 with the
 *                                         same hash, trailerField 1
 *   ecdsa-with-SHA256/384/512             DER Ecdsa-Sig-Value
 * Anything built on SHA-1 (including PSS with default parameters) and
 * any other algorithm is refused.  Returns 0 for a good signature.
 */
static const EVP_MD *
rfc7427_sha2(const ASN1_OBJECT *obj)
{
	switch (OBJ_obj2nid(obj)) {
	case NID_sha256: return EVP_sha256();
	case NID_sha384: return EVP_sha384();
	case NID_sha512: return EVP_sha512();
	}
	return NULL;
}

/* the hash of an AlgorithmIdentifier whose parameters must be NULL/absent */
static const EVP_MD *
rfc7427_sha2_algor(const X509_ALGOR *a)
{
	const ASN1_OBJECT *obj;
	int ptype;
	const void *pval;

	if (a == NULL)
		return NULL;
	X509_ALGOR_get0(&obj, &ptype, &pval, a);
	if (ptype != V_ASN1_UNDEF && ptype != V_ASN1_NULL)
		return NULL;
	return rfc7427_sha2(obj);
}

int
eay_rfc7427_verify(rc_vchar_t *octets, const uint8_t *ai, size_t ai_len,
		   rc_vchar_t *sig, rc_vchar_t *pubkey)
{
	enum { K_NONE, K_PKCS1, K_PSS, K_ECDSA } kind = K_NONE;
	const unsigned char *p;
	BPP_const unsigned char *bp;
	X509_ALGOR *alg = NULL, *mgfhash = NULL;
	RSA_PSS_PARAMS *pss = NULL;
	const ASN1_OBJECT *obj;
	int ptype;
	const void *pval;
	const EVP_MD *md = NULL, *mgfmd = NULL;
	long salt = 20;
	EVP_PKEY *pkey = NULL;
	EVP_MD_CTX *ctx = NULL;
	EVP_PKEY_CTX *pctx = NULL;
	int keytype, error = -1;

	p = ai;
	alg = d2i_X509_ALGOR(NULL, &p, (long)ai_len);
	if (alg == NULL || p != ai + ai_len) {
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
		     "RFC 7427: malformed AlgorithmIdentifier\n");
		goto end;
	}
	X509_ALGOR_get0(&obj, &ptype, &pval, alg);
	switch (OBJ_obj2nid(obj)) {
	case NID_sha256WithRSAEncryption:
		md = EVP_sha256(); kind = K_PKCS1; break;
	case NID_sha384WithRSAEncryption:
		md = EVP_sha384(); kind = K_PKCS1; break;
	case NID_sha512WithRSAEncryption:
		md = EVP_sha512(); kind = K_PKCS1; break;
	case NID_ecdsa_with_SHA256:
		md = EVP_sha256(); kind = K_ECDSA; break;
	case NID_ecdsa_with_SHA384:
		md = EVP_sha384(); kind = K_ECDSA; break;
	case NID_ecdsa_with_SHA512:
		md = EVP_sha512(); kind = K_ECDSA; break;
	case NID_rsassaPss:
		kind = K_PSS; break;
	default:
		break;
	}
	if (kind == K_NONE) {
		char oid[80];

		OBJ_obj2txt(oid, sizeof(oid), obj, 1);
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
		     "RFC 7427: unsupported signature algorithm %s\n", oid);
		goto end;
	}
	if (kind == K_PKCS1 && ptype != V_ASN1_NULL && ptype != V_ASN1_UNDEF)
		goto badparam;
	if (kind == K_ECDSA && ptype != V_ASN1_UNDEF)
		goto badparam;
	if (kind == K_PSS) {
		const ASN1_STRING *seq = pval;
		const unsigned char *q;

		/* absent hash/MGF parameters default to SHA-1: refused */
		if (ptype != V_ASN1_SEQUENCE || seq == NULL)
			goto badparam;
		q = ASN1_STRING_get0_data(seq);
		pss = d2i_RSA_PSS_PARAMS(NULL, &q, ASN1_STRING_length(seq));
		if (pss == NULL ||
		    q != ASN1_STRING_get0_data(seq) + ASN1_STRING_length(seq))
			goto badparam;
		if ((md = rfc7427_sha2_algor(pss->hashAlgorithm)) == NULL)
			goto badparam;
		if (pss->maskGenAlgorithm == NULL)
			goto badparam;
		X509_ALGOR_get0(&obj, &ptype, &pval, pss->maskGenAlgorithm);
		if (OBJ_obj2nid(obj) != NID_mgf1 || ptype != V_ASN1_SEQUENCE)
			goto badparam;
		seq = pval;
		q = ASN1_STRING_get0_data(seq);
		mgfhash = d2i_X509_ALGOR(NULL, &q, ASN1_STRING_length(seq));
		if (mgfhash == NULL ||
		    q != ASN1_STRING_get0_data(seq) + ASN1_STRING_length(seq))
			goto badparam;
		if ((mgfmd = rfc7427_sha2_algor(mgfhash)) == NULL)
			goto badparam;
		if (pss->saltLength != NULL &&
		    (salt = ASN1_INTEGER_get(pss->saltLength)) < 0)
			goto badparam;
		if (pss->trailerField != NULL &&
		    ASN1_INTEGER_get(pss->trailerField) != 1)
			goto badparam;
	}

	bp = (unsigned char *)pubkey->v;
	if ((pkey = d2i_PUBKEY(NULL, &bp, pubkey->l)) == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "failed obtaining public key: %s\n", eay_strerror());
		goto end;
	}
	keytype = EVP_PKEY_id(pkey);
	if ((kind == K_ECDSA && keytype != EVP_PKEY_EC) ||
	    (kind == K_PKCS1 && keytype != EVP_PKEY_RSA) ||
	    (kind == K_PSS && keytype != EVP_PKEY_RSA &&
	     keytype != EVP_PKEY_RSA_PSS)) {
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
		     "RFC 7427: signature algorithm does not match the "
		     "peer's key type\n");
		goto end;
	}

	if ((ctx = EVP_MD_CTX_new()) == NULL)
		goto end;
	if (EVP_DigestVerifyInit(ctx, &pctx, md, NULL, pkey) != 1)
		goto sslerr;
	if (kind == K_PSS &&
	    (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) != 1 ||
	     EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, mgfmd) != 1 ||
	     EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, (int)salt) != 1))
		goto sslerr;
	if (EVP_DigestVerify(ctx, (unsigned char *)sig->v, sig->l,
	    (unsigned char *)octets->v, octets->l) != 1) {
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
		     "RFC 7427 signature verification failed: %s\n",
		     eay_strerror());
		goto end;
	}
	if (kind == K_PSS)
		plog(PLOG_INFO, PLOGLOC, NULL,
		     "RFC 7427 signature verified: RSASSA-PSS %s "
		     "(MGF1 %s, salt %ld)\n",
		     OBJ_nid2sn(EVP_MD_type(md)), OBJ_nid2sn(EVP_MD_type(mgfmd)),
		     salt);
	else
		plog(PLOG_INFO, PLOGLOC, NULL,
		     "RFC 7427 signature verified: %s %s\n",
		     kind == K_ECDSA ? "ECDSA" : "RSASSA-PKCS1-v1_5",
		     OBJ_nid2sn(EVP_MD_type(md)));
	error = 0;
	goto end;

      sslerr:
	plog(PLOG_INTERR, PLOGLOC, NULL,
	     "RFC 7427 verify setup failed: %s\n", eay_strerror());
	goto end;
      badparam:
	plog(PLOG_PROTOERR, PLOGLOC, NULL,
	     "RFC 7427: unsupported AlgorithmIdentifier parameters\n");
      end:
	EVP_MD_CTX_free(ctx);
	EVP_PKEY_free(pkey);
	RSA_PSS_PARAMS_free(pss);
	X509_ALGOR_free(mgfhash);
	X509_ALGOR_free(alg);
	return error;
}

int
eay_ecdsa_curve_bits(rc_vchar_t *privkey)
{
	EVP_PKEY *pkey;
	BPP_const unsigned char *bp;
	int bits = 0;

	bp = (unsigned char *)privkey->v;
	pkey = d2i_AutoPrivateKey(NULL, &bp, privkey->l);
	if (pkey == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "failed obtaining private key: %s\n", eay_strerror());
		return 0;
	}
	if (EVP_PKEY_id(pkey) == EVP_PKEY_EC)
		bits = EVP_PKEY_bits(pkey);
	EVP_PKEY_free(pkey);
	return bits;
}

/*
 * get error string
 * MUST load ERR_load_crypto_strings() first.
 * XXX returns local static buffer
 */
char *
eay_strerror(void)
{
	static char ebuf[512];
	int len = 0, n;
	unsigned long l;
	char buf[200];
#if OPENSSL_VERSION_NUMBER >= 0x00904100L
	const char *file, *data;
#else
	char *file, *data;
#endif
	int line, flags;
	unsigned long es;

	es = CRYPTO_thread_id();

	while ((l = ERR_get_error_line_data(&file, &line, &data, &flags)) != 0) {
		n = snprintf(ebuf + len, sizeof(ebuf) - len,
			     "%lu:%s:%s:%d:%s ",
			     es, ERR_error_string(l, buf), file, line,
			     (flags & ERR_TXT_STRING) ? data : "");
		if (n < 0 || (size_t)n >= sizeof(ebuf) - len)
			break;
		len += n;
		if (sizeof(ebuf) < (size_t)len)
			break;
	}

	return ebuf;
}

/*
 * encrypt/decrypt with EVP interface
 */
static rc_vchar_t *
evp_encrypt(const EVP_CIPHER *ciph, rc_vchar_t *data, rc_vchar_t *key, rc_vchar_t *iv)
{
	rc_vchar_t *res;
	EVP_CIPHER_CTX *ctx = NULL;
	int outl;

	if (!iv || iv->l < (size_t)EVP_CIPHER_block_size(ciph))
		return NULL;

	/* allocate buffer for result */
	if ((res = rc_vmalloc(data->l)) == NULL)
		return NULL;

	ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "failed to allocate context\n");
		goto fail;
	}
	if (!EVP_EncryptInit(ctx, ciph, (unsigned char *)key->v, (unsigned char *)iv->v))
		goto fail;
	if (!EVP_CIPHER_CTX_set_padding(ctx, 0))
		goto fail;
	if (!EVP_EncryptUpdate(ctx, (unsigned char *)res->v, &outl, (unsigned char *)data->v,
	     data->l))
		goto fail;
	if ((size_t)outl != data->l) {
		plog(PLOG_INTERR, PLOGLOC, 0,
		     "encrypt output length does not match (%d != %lu)\n",
		     outl, (unsigned long)data->l);
		goto fail;
	}
	if (!EVP_EncryptFinal(ctx, NULL, &outl))
		goto fail;

	EVP_CIPHER_CTX_free(ctx);
	return res;

      fail:
	if (res)
		rc_vfree(res);
	if (ctx)
		EVP_CIPHER_CTX_free(ctx);
	return NULL;
}

static rc_vchar_t *
evp_decrypt(const EVP_CIPHER *ciph, rc_vchar_t *data, rc_vchar_t *key, rc_vchar_t *iv)
{
	rc_vchar_t *res;
	EVP_CIPHER_CTX *ctx = NULL;
	int outl;

	if (!iv || iv->l < (size_t)EVP_CIPHER_block_size(ciph))
		return NULL;

	/* allocate buffer for result */
	if ((res = rc_vmalloc(data->l)) == NULL)
		return NULL;

	ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "failed to allocate context\n");
		goto fail;
	}
	if (!EVP_DecryptInit(ctx, ciph, (unsigned char *)key->v, (unsigned char *)iv->v))
		goto fail;
	if (!EVP_CIPHER_CTX_set_padding(ctx, 0))
		goto fail;
	if (!EVP_DecryptUpdate(ctx, (unsigned char *)res->v, &outl, (unsigned char *)data->v,
	     data->l))
		goto fail;
	if ((size_t)outl != data->l) {
		plog(PLOG_INTERR, PLOGLOC, 0,
		     "decrypt output length does not match (%d != %lu)\n",
		     outl, (unsigned long)data->l);
		goto fail;
	}
	if (!EVP_DecryptFinal(ctx, NULL, &outl))
		goto fail;
	EVP_CIPHER_CTX_free(ctx);
	return res;

      fail:
	if (res)
		rc_vfree(res);
	if (ctx)
		EVP_CIPHER_CTX_cleanup(ctx);
	return NULL;
}

/*
 * DES-CBC
 */
rc_vchar_t *
eay_des_encrypt(rc_vchar_t *data, rc_vchar_t *key, rc_vchar_t *iv)
{
	rc_vchar_t *res;
#ifdef USE_NEW_DES_API
	DES_key_schedule ks;
#else
	des_key_schedule ks;
#endif

	if (data->l % 8)
		return NULL;

#ifdef USE_NEW_DES_API
	DES_set_key_unchecked((void *)key->v, &ks);
#else
	if (des_key_sched((void *)key->v, ks) != 0)
		return NULL;
#endif

	/* allocate buffer for result */
	if ((res = rc_vmalloc(data->l)) == NULL)
		return NULL;

	/* decryption data */
#ifdef USE_NEW_DES_API
	DES_cbc_encrypt((void *)data->v, (void *)res->v, data->l,
			&ks, (void *)iv->v, DES_ENCRYPT);
#else
	des_cbc_encrypt((void *)data->v, (void *)res->v, data->l,
			ks, (void *)iv->v, DES_ENCRYPT);
#endif

	return res;
}

rc_vchar_t *
eay_des_decrypt(rc_vchar_t *data, rc_vchar_t *key, rc_vchar_t *iv)
{
	rc_vchar_t *res;
#ifdef USE_NEW_DES_API
	DES_key_schedule ks;
#else
	des_key_schedule ks;
#endif

#ifdef USE_NEW_DES_API
	DES_set_key_unchecked((void *)key->v, &ks);
#else
	if (des_key_sched((void *)key->v, ks) != 0)
		return NULL;
#endif

	/* allocate buffer for result */
	if ((res = rc_vmalloc(data->l)) == NULL)
		return NULL;

	/* decryption data */
#ifdef USE_NEW_DES_API
	DES_cbc_encrypt((void *)data->v, (void *)res->v, data->l,
			&ks, (void *)iv->v, DES_DECRYPT);
#else
	des_cbc_encrypt((void *)data->v, (void *)res->v, data->l,
			ks, (void *)iv->v, DES_DECRYPT);
#endif

	return res;
}

int
eay_des_weakkey(rc_vchar_t *key)
{
#ifdef USE_NEW_DES_API
	return DES_is_weak_key((void *)key->v);
#else
	return des_is_weak_key((void *)key->v);
#endif
}

int
eay_des_keylen(int len)
{
	if (len != 0 && len != 64)
		return -1;
	return 64;
}

#ifdef HAVE_OPENSSL_IDEA_H
/*
 * IDEA-CBC
 */
rc_vchar_t *
eay_idea_encrypt(rc_vchar_t *data, rc_vchar_t *key, rc_vchar_t *iv)
{
	rc_vchar_t *res;
	IDEA_KEY_SCHEDULE ks;

	idea_set_encrypt_key((unsigned char *)key->v, &ks);

	/* allocate buffer for result */
	if ((res = rc_vmalloc(data->l)) == NULL)
		return NULL;

	/* decryption data */
	idea_cbc_encrypt((unsigned char *)data->v, (unsigned char *)res->v,
			 data->l, &ks, (unsigned char *)iv->v, IDEA_ENCRYPT);

	return res;
}

rc_vchar_t *
eay_idea_decrypt(rc_vchar_t *data, rc_vchar_t *key, rc_vchar_t *iv)
{
	rc_vchar_t *res;
	IDEA_KEY_SCHEDULE ks, dks;

	idea_set_encrypt_key((unsigned char *)key->v, &ks);
	idea_set_decrypt_key(&ks, &dks);

	/* allocate buffer for result */
	if ((res = rc_vmalloc(data->l)) == NULL)
		return NULL;

	/* decryption data */
	idea_cbc_encrypt((unsigned char *)data->v, (unsigned char *)res->v,
			 data->l, &dks, (unsigned char *)iv->v, IDEA_DECRYPT);

	return res;
}

int
eay_idea_weakkey(rc_vchar_t *key)
{
	return 0;		/* XXX */
}

int
eay_idea_keylen(int len)
{
	if (len != 0 && len != 128)
		return -1;
	return 128;
}
#endif

/*
 * BLOWFISH-CBC
 */
rc_vchar_t *
eay_bf_encrypt(rc_vchar_t *data, rc_vchar_t *key, rc_vchar_t *iv)
{
	rc_vchar_t *res;
	BF_KEY ks;

	BF_set_key(&ks, key->l, (unsigned char *)key->v);

	/* allocate buffer for result */
	if ((res = rc_vmalloc(data->l)) == NULL)
		return NULL;

	/* decryption data */
	BF_cbc_encrypt((unsigned char *)data->v, (unsigned char *)res->v,
		       data->l, &ks, (unsigned char *)iv->v, BF_ENCRYPT);

	return res;
}

rc_vchar_t *
eay_bf_decrypt(rc_vchar_t *data, rc_vchar_t *key, rc_vchar_t *iv)
{
	rc_vchar_t *res;
	BF_KEY ks;

	BF_set_key(&ks, key->l, (unsigned char *)key->v);

	/* allocate buffer for result */
	if ((res = rc_vmalloc(data->l)) == NULL)
		return NULL;

	/* decryption data */
	BF_cbc_encrypt((unsigned char *)data->v, (unsigned char *)res->v,
		       data->l, &ks, (unsigned char *)iv->v, BF_DECRYPT);

	return res;
}

/*ARGSUSED*/
int
eay_bf_weakkey(rc_vchar_t *key)
{
	return 0;		/* XXX to be done. refer to RFC 2451 */
}

int
eay_bf_keylen(int len)
{
	if (len == 0)
		return 448;
	if (len < 40 || len > 448)
		return -1;
	return len;
}

#ifdef HAVE_OPENSSL_RC5_H
/*
 * RC5-CBC
 */
rc_vchar_t *
eay_rc5_encrypt(rc_vchar_t *data, rc_vchar_t *key, rc_vchar_t *iv)
{
	rc_vchar_t *res;
	RC5_32_KEY ks;

	/* in RFC 2451, there is information about the number of round. */
	RC5_32_set_key(&ks, key->l, (unsigned char *)key->v, 16);

	/* allocate buffer for result */
	if ((res = rc_vmalloc(data->l)) == NULL)
		return NULL;

	/* decryption data */
	RC5_32_cbc_encrypt((unsigned char *)data->v, (unsigned char *)res->v,
			   data->l, &ks, (unsigned char *)iv->v, RC5_ENCRYPT);

	return res;
}

rc_vchar_t *
eay_rc5_decrypt(rc_vchar_t *data, rc_vchar_t *key, rc_vchar_t *iv)
{
	rc_vchar_t *res;
	RC5_32_KEY ks;

	/* in RFC 2451, there is information about the number of round. */
	RC5_32_set_key(&ks, key->l, (unsigned char *)key->v, 16);

	/* allocate buffer for result */
	if ((res = rc_vmalloc(data->l)) == NULL)
		return NULL;

	/* decryption data */
	RC5_32_cbc_encrypt((unsigned char *)data->v, (unsigned char *)res->v,
			   data->l, &ks, (unsigned char *)iv->v, RC5_DECRYPT);

	return res;
}

int
eay_rc5_weakkey(rc_vchar_t *key)
{
	return 0;		/* No known weak keys when used with 16 rounds. */

}

int
eay_rc5_keylen(int len)
{
	if (len == 0)
		return 128;
	if (len < 40 || len > 2040)
		return -1;
	return len;
}
#endif

/*
 * 3DES-CBC
 */
rc_vchar_t *
eay_3des_encrypt(rc_vchar_t *data, rc_vchar_t *key, rc_vchar_t *iv)
{
	rc_vchar_t *res;
#ifdef USE_NEW_DES_API
	DES_key_schedule ks1, ks2, ks3;
#else
	des_key_schedule ks1, ks2, ks3;
#endif

	if (key->l < 24)
		return NULL;

#ifdef USE_NEW_DES_API
	DES_set_key_unchecked((void *)key->u, &ks1);
	DES_set_key_unchecked((void *)(key->u + 8), &ks2);
	DES_set_key_unchecked((void *)(key->u + 16), &ks3);
#else
	if (des_key_sched((void *)key->u, ks1) != 0)
		return NULL;
	if (des_key_sched((void *)(key->u + 8), ks2) != 0)
		return NULL;
	if (des_key_sched((void *)(key->u + 16), ks3) != 0)
		return NULL;
#endif

	/* allocate buffer for result */
	if ((res = rc_vmalloc(data->l)) == NULL)
		return NULL;

	/* decryption data */
#ifdef USE_NEW_DES_API
	DES_ede3_cbc_encrypt((void *)data->v, (void *)res->v, data->l,
			     &ks1, &ks2, &ks3, (void *)iv->v, DES_ENCRYPT);
#else
	des_ede3_cbc_encrypt((void *)data->v, (void *)res->v, data->l,
			     ks1, ks2, ks3, (void *)iv->v, DES_ENCRYPT);
#endif

	return res;
}

rc_vchar_t *
eay_3des_decrypt(rc_vchar_t *data, rc_vchar_t *key, rc_vchar_t *iv)
{
	rc_vchar_t *res;
#ifdef USE_NEW_DES_API
	DES_key_schedule ks1, ks2, ks3;
#else
	des_key_schedule ks1, ks2, ks3;
#endif

	if (key->l < 24)
		return NULL;

#ifdef USE_NEW_DES_API
	DES_set_key_unchecked((void *)key->u, &ks1);
	DES_set_key_unchecked((void *)(key->u + 8), &ks2);
	DES_set_key_unchecked((void *)(key->u + 16), &ks3);
#else
	if (des_key_sched((void *)key->u, ks1) != 0)
		return NULL;
	if (des_key_sched((void *)(key->u + 8), ks2) != 0)
		return NULL;
	if (des_key_sched((void *)(key->u + 16), ks3) != 0)
		return NULL;
#endif

	/* allocate buffer for result */
	if ((res = rc_vmalloc(data->l)) == NULL)
		return NULL;

	/* decryption data */
#ifdef USE_NEW_DES_API
	DES_ede3_cbc_encrypt((void *)data->v, (void *)res->v, data->l,
			     &ks1, &ks2, &ks3, (void *)iv->v, DES_DECRYPT);
#else
	des_ede3_cbc_encrypt((void *)data->v, (void *)res->v, data->l,
			     ks1, ks2, ks3, (void *)iv->v, DES_DECRYPT);
#endif

	return res;
}

int
eay_3des_weakkey(rc_vchar_t *key)
{
	if (key->l < 24)
		return 0;

#ifdef USE_NEW_DES_API
	return (DES_is_weak_key((void *)key->u) ||
		DES_is_weak_key((void *)(key->u + 8)) ||
		DES_is_weak_key((void *)(key->u + 16)));
#else
	return (des_is_weak_key((void *)key->u) ||
		des_is_weak_key((void *)(key->u + 8)) ||
		des_is_weak_key((void *)(key->u + 16)));
#endif
}

int
eay_3des_keylen(int len)
{
	if (len != 0 && len != 192)
		return -1;
	return 192;
}

/*
 * CAST-CBC
 */
rc_vchar_t *
eay_cast_encrypt(rc_vchar_t *data, rc_vchar_t *key, rc_vchar_t *iv)
{
	rc_vchar_t *res;
	CAST_KEY ks;

	CAST_set_key(&ks, key->l, (unsigned char *)key->v);

	/* allocate buffer for result */
	if ((res = rc_vmalloc(data->l)) == NULL)
		return NULL;

	/* decryption data */
	CAST_cbc_encrypt((unsigned char *)data->v, (unsigned char *)res->v,
			 data->l, &ks, (unsigned char *)iv->v, DES_ENCRYPT);

	return res;
}

rc_vchar_t *
eay_cast_decrypt(rc_vchar_t *data, rc_vchar_t *key, rc_vchar_t *iv)
{
	rc_vchar_t *res;
	CAST_KEY ks;

	CAST_set_key(&ks, key->l, (unsigned char *)key->v);

	/* allocate buffer for result */
	if ((res = rc_vmalloc(data->l)) == NULL)
		return NULL;

	/* decryption data */
	CAST_cbc_encrypt((unsigned char *)data->v, (unsigned char *)res->v,
			 data->l, &ks, (unsigned char *)iv->v, DES_DECRYPT);

	return res;
}

/*ARGSUSED*/
int
eay_cast_weakkey(rc_vchar_t *key)
{
	return 0;		/* No known weak keys. */
}

int
eay_cast_keylen(int len)
{
	if (len == 0)
		return 128;
	if (len < 40 || len > 128)
		return -1;
	return len;
}

/*
 * AES(RIJNDAEL)-CBC
 */
rc_vchar_t *
eay_aes_encrypt(rc_vchar_t *data, rc_vchar_t *key, rc_vchar_t *iv)
{
	const EVP_CIPHER *ciph;

	switch (key->l) {
	case 128 / 8:
		ciph = EVP_aes_128_cbc();
		break;
	case 192 / 8:
		ciph = EVP_aes_192_cbc();
		break;
	case 256 / 8:
		ciph = EVP_aes_256_cbc();
		break;
	default:
		plog(PLOG_INTERR, PLOGLOC, 0,
		     "unsupported key length %lu\n", (unsigned long)key->l * 8);
		return NULL;
		break;
	}

	return evp_encrypt(ciph, data, key, iv);
}

rc_vchar_t *
eay_aes_decrypt(rc_vchar_t *data, rc_vchar_t *key, rc_vchar_t *iv)
{
	const EVP_CIPHER *ciph;

	switch (key->l) {
	case 128 / 8:
		ciph = EVP_aes_128_cbc();
		break;
	case 192 / 8:
		ciph = EVP_aes_192_cbc();
		break;
	case 256 / 8:
		ciph = EVP_aes_256_cbc();
		break;
	default:
		plog(PLOG_INTERR, PLOGLOC, 0,
		     "unsupported key length %lu\n", (unsigned long)key->l * 8);
		return NULL;
		break;
	}

	return evp_decrypt(ciph, data, key, iv);
}

/*ARGSUSED*/
int
eay_aes_weakkey(rc_vchar_t *key)
{
	return 0;
}

int
eay_aes_keylen(int len)
{
	if (len != 128 && len != 192 && len != 256)
		return -1;
	return len;
}

/*
 * AES-CTR
 */
rc_vchar_t *
eay_aes_ctr(rc_vchar_t *data, rc_vchar_t *key, rc_vchar_t *iv)
{
	/* there's no difference of encrypt and decrypt for AES-CTR */

	/* (rfc3686)
	 * The size of the requested KEYMAT MUST be four octets longer than is
	 * needed for the associated AES key.  The keying material is used as
	 * follows:
	 *
	 * AES-CTR with a 128 bit key
	 * The KEYMAT requested for each AES-CTR key is 20 octets.  The first
	 * 16 octets are the 128-bit AES key, and the remaining four octets
	 * are used as the nonce value in the counter block.
	 *
	 * AES-CTR with a 192 bit key
	 * The KEYMAT requested for each AES-CTR key is 28 octets.  The first
	 * 24 octets are the 192-bit AES key, and the remaining four octets
	 * are used as the nonce value in the counter block.
	 *
	 * AES-CTR with a 256 bit key
	 * The KEYMAT requested for each AES-CTR key is 36 octets.  The first
	 * 32 octets are the 256-bit AES key, and the remaining four octets
	 * are used as the nonce value in the counter block.
	 */

	int len;
	size_t aes_len;
	const EVP_CIPHER *ciph;
	unsigned char ctrblk[AES_BLOCK_SIZE];
	rc_vchar_t *resultbuf = NULL;
	EVP_CIPHER_CTX *ctx = NULL;

	/*
	 * if (data->l > AES_BLOCK_SIZE * UINT32_MAX) return 0;
	 */

	if (!key || !iv || iv->l != AES_CTR_IV_SIZE) {
		plog(PLOG_INTERR, PLOGLOC, 0, "bad iv size");
		return 0;
	}
	/*
	 * RFC 3686: KEYMAT is AES key || 4-octet nonce.  The counter block
	 * is nonce || IV || block counter, and the block counter starts at 1.
	 * OpenSSL CTR takes that 16-octet block as its IV and a bare AES key.
	 * Passing the 8-octet IV and the nonce-bearing key makes each seat
	 * read a different keystream, so IKE_AUTH decrypts to garbage and
	 * ikev2_check_payloads reports malformed payload format.
	 */
	if (key->l < 4) {
		plog(PLOG_INTERR, PLOGLOC, 0, "AES-CTR key missing nonce");
		return 0;
	}
	aes_len = key->l - 4;
	switch (aes_len) {
	case 16:
		ciph = EVP_aes_128_ctr();
		break;
	case 24:
		ciph = EVP_aes_192_ctr();
		break;
	case 32:
		ciph = EVP_aes_256_ctr();
		break;
	default:
		plog(PLOG_INTERR, PLOGLOC, 0,
		     "unsupported AES-CTR key length %lu\n",
		     (unsigned long)aes_len * 8);
		return 0;
	}
	memcpy(ctrblk, key->v + aes_len, 4);
	memcpy(ctrblk + 4, iv->v, AES_CTR_IV_SIZE);
	ctrblk[12] = 0;
	ctrblk[13] = 0;
	ctrblk[14] = 0;
	ctrblk[15] = 1;

	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL) {
		plog(PLOG_INTERR, PLOGLOC, 0, "EVP_CIPHER_CTX_new failed");
		goto fail;
	}

	if (!EVP_EncryptInit_ex(ctx, ciph, NULL, (unsigned char *)key->v, ctrblk)) {
		plog(PLOG_INTERR, PLOGLOC, 0, "EVP_EncryptInit_ex failed");
		goto fail;
	}
	EVP_CIPHER_CTX_set_padding(ctx, 0);

	resultbuf = rc_vmalloc(data->l);
	if (!resultbuf) {
		plog(PLOG_INTERR, PLOGLOC, 0, "allocate resultbuf failed");
		goto fail;
	}

	if (!EVP_EncryptUpdate(ctx, (unsigned char *)resultbuf->v, &len, (unsigned char *)data->v, data->l)) {
		plog(PLOG_INTERR, PLOGLOC, 0, "EVP_EncryptUpdate failed");
		goto fail;
	}

	if (!EVP_EncryptFinal_ex(ctx, (unsigned char *)resultbuf->v + len, &len)) {
		plog(PLOG_INTERR, PLOGLOC, 0, "EVP_EncryptFinal_ex failed");
		goto fail;
	}

	EVP_CIPHER_CTX_free(ctx);
	return resultbuf;

fail:
	EVP_CIPHER_CTX_free(ctx);
	if (resultbuf)
		rc_free(resultbuf);

	return NULL;
}

/*
 * RFC 5282 AES-GCM for IKEv2 Encrypted Payload.
 * key: AES-128/192/256 key || 4-octet salt
 * iv: 8 octets (sent in the payload)
 * nonce: salt || iv (12 octets)
 * encrypt: plaintext -> ciphertext || ICV16
 * decrypt: ciphertext || ICV16 -> plaintext
 */
static const EVP_CIPHER *
eay_aes_gcm_cipher(size_t aes_key_len)
{
	switch (aes_key_len) {
	case 16:
		return EVP_aes_128_gcm();
	case 24:
		return EVP_aes_192_gcm();
	case 32:
		return EVP_aes_256_gcm();
	default:
		return NULL;
	}
}

static int
eay_aes_gcm_nonce(unsigned char nonce[AES_GCM_NONCE_SIZE],
		  rc_vchar_t *key, rc_vchar_t *iv, size_t *aes_key_len)
{
	if (!key || !iv || iv->l != AES_GCM_IV_SIZE)
		return -1;
	if (key->l < AES_GCM_SALT_SIZE)
		return -1;
	*aes_key_len = key->l - AES_GCM_SALT_SIZE;
	if (eay_aes_gcm_cipher(*aes_key_len) == NULL)
		return -1;
	memcpy(nonce, key->u + *aes_key_len, AES_GCM_SALT_SIZE);
	memcpy(nonce + AES_GCM_SALT_SIZE, iv->v, AES_GCM_IV_SIZE);
	return 0;
}

rc_vchar_t *
eay_aes_gcm_ike_encrypt(rc_vchar_t *data, rc_vchar_t *key, rc_vchar_t *iv,
			rc_vchar_t *aad)
{
	unsigned char nonce[AES_GCM_NONCE_SIZE];
	size_t aes_key_len;
	EVP_CIPHER_CTX *ctx = NULL;
	rc_vchar_t *out = NULL;
	int len = 0, len2 = 0;
	const EVP_CIPHER *ciph;

	if (!data || eay_aes_gcm_nonce(nonce, key, iv, &aes_key_len) != 0)
		return NULL;
	ciph = eay_aes_gcm_cipher(aes_key_len);
	ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		return NULL;
	out = rc_vmalloc(data->l + AES_GCM_ICV_SIZE);
	if (!out)
		goto fail;
	if (!EVP_EncryptInit_ex(ctx, ciph, NULL, NULL, NULL))
		goto fail;
	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
				 AES_GCM_NONCE_SIZE, NULL))
		goto fail;
	if (!EVP_EncryptInit_ex(ctx, NULL, NULL,
				(unsigned char *)key->v, nonce))
		goto fail;
	if (aad && aad->l > 0) {
		if (!EVP_EncryptUpdate(ctx, NULL, &len,
				       (unsigned char *)aad->v, (int)aad->l))
			goto fail;
	}
	if (!EVP_EncryptUpdate(ctx, (unsigned char *)out->v, &len,
			       (unsigned char *)data->v, (int)data->l))
		goto fail;
	if (!EVP_EncryptFinal_ex(ctx, (unsigned char *)out->v + len, &len2))
		goto fail;
	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_GCM_ICV_SIZE,
				 (unsigned char *)out->v + data->l))
		goto fail;
	EVP_CIPHER_CTX_free(ctx);
	return out;
fail:
	EVP_CIPHER_CTX_free(ctx);
	if (out)
		rc_vfree(out);
	return NULL;
}

rc_vchar_t *
eay_aes_gcm_ike_decrypt(rc_vchar_t *data, rc_vchar_t *key, rc_vchar_t *iv,
			rc_vchar_t *aad)
{
	unsigned char nonce[AES_GCM_NONCE_SIZE];
	size_t aes_key_len;
	size_t ct_len;
	EVP_CIPHER_CTX *ctx = NULL;
	rc_vchar_t *out = NULL;
	int len = 0, len2 = 0;
	const EVP_CIPHER *ciph;

	if (!data || data->l < AES_GCM_ICV_SIZE)
		return NULL;
	if (eay_aes_gcm_nonce(nonce, key, iv, &aes_key_len) != 0)
		return NULL;
	ciph = eay_aes_gcm_cipher(aes_key_len);
	ct_len = data->l - AES_GCM_ICV_SIZE;
	ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		return NULL;
	out = rc_vmalloc(ct_len);
	if (!out)
		goto fail;
	if (!EVP_DecryptInit_ex(ctx, ciph, NULL, NULL, NULL))
		goto fail;
	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
				 AES_GCM_NONCE_SIZE, NULL))
		goto fail;
	if (!EVP_DecryptInit_ex(ctx, NULL, NULL,
				(unsigned char *)key->v, nonce))
		goto fail;
	if (aad && aad->l > 0) {
		if (!EVP_DecryptUpdate(ctx, NULL, &len,
				       (unsigned char *)aad->v, (int)aad->l))
			goto fail;
	}
	if (ct_len > 0 &&
	    !EVP_DecryptUpdate(ctx, (unsigned char *)out->v, &len,
			       (unsigned char *)data->v, (int)ct_len))
		goto fail;
	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_GCM_ICV_SIZE,
				 (unsigned char *)data->v + ct_len))
		goto fail;
	if (!EVP_DecryptFinal_ex(ctx, (unsigned char *)out->v + len, &len2))
		goto fail;
	EVP_CIPHER_CTX_free(ctx);
	return out;
fail:
	EVP_CIPHER_CTX_free(ctx);
	if (out)
		rc_vfree(out);
	return NULL;
}

/* for ipsec part */
int
eay_null_hashlen(void)
{
	return 0;
}

int
eay_kpdk_hashlen(void)
{
	return 0;
}

int
eay_twofish_keylen(int len)
{
	if (len < 0 || len > 256)
		return -1;
	return len;
}

/*ARGSUSED*/
int
eay_null_keylen(int len)
{
	return 0;
}

/*
 * HMAC functions
 */
static caddr_t
eay_hmac_init(rc_vchar_t *key, const EVP_MD *md)
{
	HMAC_CTX *c = HMAC_CTX_new();

	HMAC_Init_ex(c, key->v, key->l, md, NULL);

	return (caddr_t)c;
}

void
eay_hmac_dispose(HMAC_CTX *c)
{
	HMAC_CTX_free(c);
}

#ifdef WITH_SHA2
/*
 * HMAC SHA2-512
 */
rc_vchar_t *
eay_hmacsha2_512_one(rc_vchar_t *key, rc_vchar_t *data)
{
	rc_vchar_t *res;
	caddr_t ctx;

	ctx = eay_hmacsha2_512_init(key);
	eay_hmacsha2_512_update(ctx, data);
	res = eay_hmacsha2_512_final(ctx);

	return (res);
}

caddr_t
eay_hmacsha2_512_init(rc_vchar_t *key)
{
	return eay_hmac_init(key, EVP_sha512());
}

void
eay_hmacsha2_512_update(caddr_t c, rc_vchar_t *data)
{
	HMAC_Update((HMAC_CTX *)c, (unsigned char *)data->v, data->l);
}

rc_vchar_t *
eay_hmacsha2_512_final(caddr_t c)
{
	rc_vchar_t *res;
	unsigned int l;

	if ((res = rc_vmalloc(SHA512_DIGEST_LENGTH)) == 0)
		return NULL;

	HMAC_Final((HMAC_CTX *)c, (unsigned char *)res->v, &l);
	res->l = l;
	eay_hmac_dispose((HMAC_CTX *)c);

	if (SHA512_DIGEST_LENGTH != res->l) {
#ifndef EAYDEBUG
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
		     "hmac sha2_512 length mismatch %lu.\n", (unsigned long)res->l);
#else
		printf("hmac sha2_512 length mismatch %lu.\n", (unsigned long)res->l);
#endif
		rc_vfree(res);
		return NULL;
	}

	return (res);
}

/*
 * HMAC SHA2-384
 */
rc_vchar_t *
eay_hmacsha2_384_one(rc_vchar_t *key, rc_vchar_t *data)
{
	rc_vchar_t *res;
	caddr_t ctx;

	ctx = eay_hmacsha2_384_init(key);
	eay_hmacsha2_384_update(ctx, data);
	res = eay_hmacsha2_384_final(ctx);

	return (res);
}

caddr_t
eay_hmacsha2_384_init(rc_vchar_t *key)
{
	return eay_hmac_init(key, EVP_sha384());
}

void
eay_hmacsha2_384_update(caddr_t c, rc_vchar_t *data)
{
	HMAC_Update((HMAC_CTX *)c, (unsigned char *)data->v, data->l);
}

rc_vchar_t *
eay_hmacsha2_384_final(caddr_t c)
{
	rc_vchar_t *res;
	unsigned int l;

	if ((res = rc_vmalloc(SHA384_DIGEST_LENGTH)) == 0)
		return NULL;

	HMAC_Final((HMAC_CTX *)c, (unsigned char *)res->v, &l);
	res->l = l;
	eay_hmac_dispose((HMAC_CTX *)c);

	if (SHA384_DIGEST_LENGTH != res->l) {
#ifndef EAYDEBUG
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
		     "hmac sha2_384 length mismatch %lu.\n", (unsigned long)res->l);
#else
		printf("hmac sha2_384 length mismatch %lu.\n", (unsigned long)res->l);
#endif
		rc_vfree(res);
		return NULL;
	}

	return (res);
}

/*
 * HMAC SHA2-256
 */
rc_vchar_t *
eay_hmacsha2_256_one(rc_vchar_t *key, rc_vchar_t *data)
{
	rc_vchar_t *res;
	caddr_t ctx;

	ctx = eay_hmacsha2_256_init(key);
	eay_hmacsha2_256_update(ctx, data);
	res = eay_hmacsha2_256_final(ctx);

	return (res);
}

caddr_t
eay_hmacsha2_256_init(rc_vchar_t *key)
{
	return eay_hmac_init(key, EVP_sha256());
}

void
eay_hmacsha2_256_update(caddr_t c, rc_vchar_t *data)
{
	HMAC_Update((HMAC_CTX *)c, (unsigned char *)data->v, data->l);
}

rc_vchar_t *
eay_hmacsha2_256_final(caddr_t c)
{
	rc_vchar_t *res;
	unsigned int l;

	if ((res = rc_vmalloc(SHA256_DIGEST_LENGTH)) == 0)
		return NULL;

	HMAC_Final((HMAC_CTX *)c, (unsigned char *)res->v, &l);
	res->l = l;
	eay_hmac_dispose((HMAC_CTX *)c);

	if (SHA256_DIGEST_LENGTH != res->l) {
#ifndef EAYDEBUG
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
		     "hmac sha2_256 length mismatch %lu.\n", (unsigned long)res->l);
#else
		printf("hmac sha2_256 length mismatch %lu.\n", (unsigned long)res->l);
#endif
		rc_vfree(res);
		return NULL;
	}

	return (res);
}
#endif				/* WITH_SHA2 */

/*
 * HMAC SHA1
 */
rc_vchar_t *
eay_hmacsha1_one(rc_vchar_t *key, rc_vchar_t *data)
{
	rc_vchar_t *res;
	caddr_t ctx;

	ctx = eay_hmacsha1_init(key);
	eay_hmacsha1_update(ctx, data);
	res = eay_hmacsha1_final(ctx);

	return (res);
}

caddr_t
eay_hmacsha1_init(rc_vchar_t *key)
{
	return eay_hmac_init(key, EVP_sha1());
}

void
eay_hmacsha1_update(caddr_t c, rc_vchar_t *data)
{
	HMAC_Update((HMAC_CTX *)c, (unsigned char *)data->v, data->l);
}

rc_vchar_t *
eay_hmacsha1_final(caddr_t c)
{
	rc_vchar_t *res;
	unsigned int l;

	if ((res = rc_vmalloc(SHA_DIGEST_LENGTH)) == 0)
		return NULL;

	HMAC_Final((HMAC_CTX *)c, (unsigned char *)res->v, &l);
	res->l = l;
	eay_hmac_dispose((HMAC_CTX *)c);

	if (SHA_DIGEST_LENGTH != res->l) {
#ifndef EAYDEBUG
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
		     "hmac sha1 length mismatch %lu.\n", (unsigned long)res->l);
#else
		printf("hmac sha1 length mismatch %lu.\n", (unsigned long)res->l);
#endif
		rc_vfree(res);
		return NULL;
	}

	return (res);
}

/*
 * HMAC MD5
 */
rc_vchar_t *
eay_hmacmd5_one(rc_vchar_t *key, rc_vchar_t *data)
{
	rc_vchar_t *res;
	caddr_t ctx;

	ctx = eay_hmacmd5_init(key);
	eay_hmacmd5_update(ctx, data);
	res = eay_hmacmd5_final(ctx);

	return (res);
}

caddr_t
eay_hmacmd5_init(rc_vchar_t *key)
{
	return eay_hmac_init(key, EVP_md5());
}

void
eay_hmacmd5_update(caddr_t c, rc_vchar_t *data)
{
	HMAC_Update((HMAC_CTX *)c, (unsigned char *)data->v, data->l);
}

rc_vchar_t *
eay_hmacmd5_final(caddr_t c)
{
	rc_vchar_t *res;
	unsigned int l;

	if ((res = rc_vmalloc(MD5_DIGEST_LENGTH)) == 0)
		return NULL;

	HMAC_Final((HMAC_CTX *)c, (unsigned char *)res->v, &l);
	res->l = l;
	eay_hmac_dispose((HMAC_CTX *)c);

	if (MD5_DIGEST_LENGTH != res->l) {
#ifndef EAYDEBUG
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
		     "hmac md5 length mismatch %lu.\n", (unsigned long)res->l);
#else
		printf("hmac md5 length mismatch %lu.\n", (unsigned long)res->l);
#endif
		rc_vfree(res);
		return NULL;
	}

	return (res);
}

/*
 * AES-XCBC-PRF-128 (RFC3664)
 */
#define	REPEAT4(x_)	x_, x_, x_, x_
#define	REPEAT16(x_)	REPEAT4(x_), REPEAT4(x_), REPEAT4(x_), REPEAT4(x_)

typedef struct aescbcmac_ctx {
	AES_KEY k1;
	uint8_t k2[AES_XCBC_BLOCKLEN];
	uint8_t k3[AES_XCBC_BLOCKLEN];
	uint8_t e[AES_XCBC_BLOCKLEN];
	uint8_t m[AES_XCBC_BLOCKLEN];
	int mlen;
} CBCMAC_CTX;

#if 0
typedef struct cbcmac_ctx {
	caddr_t *k1;
	void (*encrypt) ();
	void (*dispose_k1) ();
	uint8_t k2[MAX_CBCMAC_BLOCKLEN];
	uint8_t k3[MAX_CBCMAC_BLOCKLEN];
	uint8_t e[MAX_CBCMAC_BLOCKLEN];
	uint8_t m[MAX_CBCMAC_BLOCKLEN];
	int mlen;
};
#endif

/*
 * AES-XCBC-MAC (RFC3664) / AES-XCBC-PRF-128 (RFC4434)
 */
#if 0
static int
eay_aes_xcbc_mac_keylen(int len)
{
	if (len == 0)
		return AES_XCBC_KEYLEN;
	if (len != AES_XCBC_KEYLEN)
		return -1;
	return len;
}
#endif

int
eay_aes_xcbc_hashlen(void)
{
	return AES_XCBC_BLOCKLEN << 3;
}

caddr_t
eay_aes_xcbc_mac_init(rc_vchar_t *key)
{
	rc_vchar_t	*k = 0;
	CBCMAC_CTX *c = 0;
	AES_KEY aes_key;
	uint8_t k1[AES_XCBC_BLOCKLEN];
	static const uint8_t const1[] = { REPEAT16(0x01) };
	static const uint8_t const2[] = { REPEAT16(0x02) };
	static const uint8_t const3[] = { REPEAT16(0x03) };
	const size_t aesxcbc_keylen = AES_XCBC_KEYLEN / 8;

	if (key->l == aesxcbc_keylen) {
		k = rc_vdup(key);
	} else if (key->l < aesxcbc_keylen) {
		k = rc_vmalloc(aesxcbc_keylen);
		if (!k)
			return 0;
		memcpy(k->u, key->u, key->l);
		memset(k->u + key->l, 0, k->l - key->l);
	} else {
		static uint8_t zerokey_bits[] = { REPEAT16(0) };
		static rc_vchar_t zerokey = VCHAR_INIT((caddr_t)zerokey_bits,
						       sizeof(zerokey_bits));

		k = eay_aes_xcbc_mac_one(&zerokey, key);
	}
	if (!k)
		return 0;

	if (AES_set_encrypt_key((unsigned char *)k->v, k->l * 8, &aes_key)
	    != 0)
		goto fail;
	c = racoon_malloc(sizeof(*c));
	if (!c)
		goto fail;
	AES_encrypt(const1, k1, &aes_key);
	if (AES_set_encrypt_key(k1, 128, &c->k1) != 0)
		goto fail;
	AES_encrypt(const2, c->k2, &aes_key);
	AES_encrypt(const3, c->k3, &aes_key);
	memset(c->e, 0, sizeof(c->e));
	c->mlen = 0;

	rc_vfree(k);
	return (caddr_t)c;

      fail:
	if (c)
		racoon_free(c);
	if (k)
		rc_vfree(k);
	return 0;
}

void
eay_aes_xcbc_mac_update(caddr_t ctx, rc_vchar_t *data)
{
	CBCMAC_CTX *c = (CBCMAC_CTX *)ctx;
	unsigned char *p;
	int i;
	size_t len;
	size_t l;

	len = data->l;
	p = (unsigned char *)data->v;
	while (len > 0) {
		assert(c->mlen <= AES_XCBC_BLOCKLEN);
		if (c->mlen == AES_XCBC_BLOCKLEN) {
			for (i = 0; i < AES_XCBC_BLOCKLEN; ++i)
				c->m[i] ^= c->e[i];
			AES_encrypt(c->m, c->e, &c->k1);
			c->mlen = 0;
		}
		l = len;
		if (l > (size_t)AES_XCBC_BLOCKLEN - c->mlen)
			l = AES_XCBC_BLOCKLEN - c->mlen;
		memcpy(&c->m[c->mlen], p, l);
		c->mlen += l;
		len -= l;
		p += l;
	}
}

static void
eay_aes_xcbc_mac_dispose(caddr_t ctx)
{
	CBCMAC_CTX *c = (CBCMAC_CTX *)ctx;

	memset(c, 0, sizeof(*c));
	racoon_free(c);
}

rc_vchar_t *
eay_aes_xcbc_mac_final(caddr_t ctx)
{
	CBCMAC_CTX *c = (CBCMAC_CTX *)ctx;
	int i;
	rc_vchar_t *result;

	if (c->mlen == AES_XCBC_BLOCKLEN) {
		for (i = 0; i < AES_XCBC_BLOCKLEN; ++i)
			c->m[i] ^= c->e[i] ^ c->k2[i];
	} else {
		c->m[c->mlen] = 0x80;
		for (i = c->mlen + 1; i < AES_XCBC_BLOCKLEN; ++i)
			c->m[i] = 0;
		for (i = 0; i < AES_XCBC_BLOCKLEN; ++i)
			c->m[i] ^= c->e[i] ^ c->k3[i];
	}
	AES_encrypt(c->m, c->e, &c->k1);

	result = rc_vmalloc(AES_XCBC_BLOCKLEN);
	if (!result)
		return 0;
	memcpy(result->v, c->e, AES_XCBC_BLOCKLEN);

	eay_aes_xcbc_mac_dispose(ctx);

	return result;
}

rc_vchar_t *
eay_aes_xcbc_mac_one(rc_vchar_t *key, rc_vchar_t *data)
{
	rc_vchar_t *res;
	caddr_t ctx;

	ctx = eay_aes_xcbc_mac_init(key);
	eay_aes_xcbc_mac_update(ctx, data);
	res = eay_aes_xcbc_mac_final(ctx);

	return (res);
}

/*
 * CMAC (FIPS SP800-38B)
 * (RFC4615)
 */
static void
gf_mult(uint8_t *l, uint8_t *k, unsigned int r)
{
	int i;
	int value;
	int carryover;

	/*
	 * if (MSB(L) == 0
	 *    { L <<= 1         }
	 * else
	 *    { L <<= 1; L ^= R }
	 */
	carryover = 0;
	for (i = AES_BLOCK_SIZE; --i >= 0;) {
		value = l[i] << 1;
		k[i] = value | carryover;
		carryover = value >> 8;
	}
	if (carryover)
		k[AES_BLOCK_SIZE - 1] ^= r;
}

caddr_t
eay_aes_cmac_init(rc_vchar_t *key)
{
	rc_vchar_t *k = 0;
	CBCMAC_CTX *c = 0;
	static const uint8_t zero[AES_BLOCK_SIZE] = { REPEAT16(0) };
	static const uint8_t R128 = 0x87;
	uint8_t L[AES_BLOCK_SIZE];
	const size_t aescmac_keylen = 128 / 8;

	if (key->l == aescmac_keylen) {
		k = rc_vdup(key);
	} else if (key->l < aescmac_keylen) {
		k = rc_vmalloc(aescmac_keylen);
		if (!k)
			return 0;
		memcpy(k->u, key->u, key->l);
		memset(k->u + key->l, 0, k->l - key->l);
	} else {
		static uint8_t zerokey_bits[] = { REPEAT16(0) };
		static rc_vchar_t zerokey = VCHAR_INIT((caddr_t)zerokey_bits,
						       sizeof(zerokey_bits));

		k = eay_aes_cmac_one(&zerokey, key);
	}
	if (!k)
		return 0;

	c = racoon_calloc(1, sizeof(*c));
	if (!c)
		goto fail;

	if (AES_set_encrypt_key((unsigned char *)k->v, k->l * 8, &c->k1)
	    != 0)
		goto fail;
	AES_encrypt(zero, L, &c->k1);
	//gf_mult(L, &c->k2, R128);
	//gf_mult(&c->k2, &c->k3, R128);
	gf_mult(L, c->k2, R128);
	gf_mult(c->k2, c->k3, R128);
	OPENSSL_cleanse(L, sizeof(L));

	rc_vfreez(k);		/* key copy is only needed for k1 schedule */
	return (caddr_t)c;

      fail:
	if (c)
		racoon_free(c);
	if (k)
		rc_vfreez(k);
	return 0;
}

void
eay_aes_cmac_update(caddr_t ctx, rc_vchar_t *data)
{
	eay_aes_xcbc_mac_update(ctx, data);
}

void
eay_aes_cmac_dispose(caddr_t ctx)
{
	eay_aes_xcbc_mac_dispose(ctx);
}

rc_vchar_t *
eay_aes_cmac_final(caddr_t ctx)
{
	return eay_aes_xcbc_mac_final(ctx);
}

rc_vchar_t *
eay_aes_cmac_one(rc_vchar_t *key, rc_vchar_t *data)
{
	rc_vchar_t *res;
	caddr_t ctx;

	ctx = eay_aes_cmac_init(key);
	if (ctx == NULL)
		return NULL;	/* OOM: update would deref NULL */
	eay_aes_cmac_update(ctx, data);
	res = eay_aes_cmac_final(ctx);

	return (res);
}

int
eay_aes_cmac_hashlen(void)
{
	return AES_XCBC_BLOCKLEN << 3;
}

#ifdef WITH_SHA2
/*
 * SHA2-512 functions
 */
caddr_t
eay_sha2_512_init(void)
{
	SHA512_CTX *c = racoon_malloc(sizeof(*c));

	SHA512_Init(c);

	return ((caddr_t)c);
}

void
eay_sha2_512_update(caddr_t c, rc_vchar_t *data)
{
	SHA512_Update((SHA512_CTX *)c, (unsigned char *)data->v, data->l);

	return;
}

rc_vchar_t *
eay_sha2_512_final(caddr_t c)
{
	rc_vchar_t *res;

	if ((res = rc_vmalloc(SHA512_DIGEST_LENGTH)) == 0)
		return (0);

	SHA512_Final((unsigned char *)res->v, (SHA512_CTX *)c);
	(void)racoon_free(c);

	return (res);
}

rc_vchar_t *
eay_sha2_512_one(rc_vchar_t *data)
{
	caddr_t ctx;
	rc_vchar_t *res;

	ctx = eay_sha2_512_init();
	eay_sha2_512_update(ctx, data);
	res = eay_sha2_512_final(ctx);

	return (res);
}
#endif

int
eay_sha2_512_hashlen(void)
{
	return SHA512_DIGEST_LENGTH << 3;
}

#ifdef WITH_SHA2
/*
 * SHA2-384 functions
 */
caddr_t
eay_sha2_384_init(void)
{
	SHA384_CTX *c = racoon_malloc(sizeof(*c));

	SHA384_Init(c);

	return ((caddr_t)c);
}

void
eay_sha2_384_update(caddr_t c, rc_vchar_t *data)
{
	SHA384_Update((SHA384_CTX *)c, (unsigned char *)data->v, data->l);

	return;
}

rc_vchar_t *
eay_sha2_384_final(caddr_t c)
{
	rc_vchar_t *res;

	if ((res = rc_vmalloc(SHA384_DIGEST_LENGTH)) == 0)
		return (0);

	SHA384_Final((unsigned char *)res->v, (SHA384_CTX *)c);
	(void)racoon_free(c);

	return (res);
}

rc_vchar_t *
eay_sha2_384_one(rc_vchar_t *data)
{
	caddr_t ctx;
	rc_vchar_t *res;

	ctx = eay_sha2_384_init();
	eay_sha2_384_update(ctx, data);
	res = eay_sha2_384_final(ctx);

	return (res);
}
#endif

int
eay_sha2_384_hashlen(void)
{
	return SHA384_DIGEST_LENGTH << 3;
}

#ifdef WITH_SHA2
/*
 * SHA2-256 functions
 */
caddr_t
eay_sha2_256_init(void)
{
	SHA256_CTX *c = racoon_malloc(sizeof(*c));

	SHA256_Init(c);

	return ((caddr_t)c);
}

void
eay_sha2_256_update(caddr_t c, rc_vchar_t *data)
{
	SHA256_Update((SHA256_CTX *)c, (unsigned char *)data->v, data->l);

	return;
}

rc_vchar_t *
eay_sha2_256_final(caddr_t c)
{
	rc_vchar_t *res;

	if ((res = rc_vmalloc(SHA256_DIGEST_LENGTH)) == 0)
		return (0);

	SHA256_Final((unsigned char *)res->v, (SHA256_CTX *)c);
	(void)racoon_free(c);

	return (res);
}

rc_vchar_t *
eay_sha2_256_one(rc_vchar_t *data)
{
	caddr_t ctx;
	rc_vchar_t *res;

	ctx = eay_sha2_256_init();
	eay_sha2_256_update(ctx, data);
	res = eay_sha2_256_final(ctx);

	return (res);
}
#endif

int
eay_sha2_256_hashlen(void)
{
	return SHA256_DIGEST_LENGTH << 3;
}

/*
 * SHA functions
 */
caddr_t
eay_sha1_init(void)
{
	EVP_MD_CTX *c;

	c = EVP_MD_CTX_create();
	if (!EVP_DigestInit_ex(c, EVP_sha1(), NULL)) {
		plog(PLOG_INTERR, PLOGLOC, 0,
		     "EVP_DigestInit_ex failed: %s\n", eay_strerror());
		EVP_MD_CTX_destroy(c);
		return 0;
	}
	return (caddr_t)c;
}

void
eay_sha1_update(caddr_t c, rc_vchar_t *data)
{
	EVP_MD_CTX *ctx = (EVP_MD_CTX *)c;

	if (!EVP_DigestUpdate(ctx, data->v, data->l)) {
		plog(PLOG_INTERR, PLOGLOC, 0,
		     "EVP_DigestUpdate failed: %s\n", eay_strerror());
		return;
	}
	return;
}

rc_vchar_t *
eay_sha1_final(caddr_t c)
{
	EVP_MD_CTX *ctx = (EVP_MD_CTX *)c;
	rc_vchar_t *res;

	if ((res = rc_vmalloc(SHA_DIGEST_LENGTH)) == 0)
		return (0);

	if (!EVP_DigestFinal(ctx, (unsigned char *)res->v, NULL)) {
		plog(PLOG_INTERR, PLOGLOC, 0,
		     "EVP_DigestFinal failed: %s\n", eay_strerror());
		rc_vfree(res);
		res = 0;
	}
	EVP_MD_CTX_destroy(ctx);
	return res;
}

rc_vchar_t *
eay_sha1_one(rc_vchar_t *data)
{
	caddr_t ctx;
	rc_vchar_t *res;

	ctx = eay_sha1_init();
	eay_sha1_update(ctx, data);
	res = eay_sha1_final(ctx);

	return (res);
}

int
eay_sha1_hashlen(void)
{
	return SHA_DIGEST_LENGTH << 3;
}

/*
 * MD5 functions
 */
caddr_t
eay_md5_init(void)
{
	EVP_MD_CTX *c;

	c = EVP_MD_CTX_create();
	if (!EVP_DigestInit_ex(c, EVP_md5(), NULL)) {
		plog(PLOG_INTERR, PLOGLOC, 0,
		     "EVP_DigestInit_ex failed: %s\n", eay_strerror());
		EVP_MD_CTX_destroy(c);
		return 0;
	}
	return (caddr_t)c;
}

void
eay_md5_update(caddr_t c, rc_vchar_t *data)
{
	EVP_MD_CTX *ctx = (EVP_MD_CTX *)c;

	if (!EVP_DigestUpdate(ctx, data->v, data->l)) {
		plog(PLOG_INTERR, PLOGLOC, 0,
		     "EVP_DigestUpdate failed: %s\n", eay_strerror());
		return;
	}
	return;
}

rc_vchar_t *
eay_md5_final(caddr_t c)
{
	EVP_MD_CTX *ctx = (EVP_MD_CTX *)c;
	rc_vchar_t *res;

	if ((res = rc_vmalloc(MD5_DIGEST_LENGTH)) == 0)
		return (0);

	if (!EVP_DigestFinal(ctx, (unsigned char *)res->v, NULL)) {
		plog(PLOG_INTERR, PLOGLOC, 0,
		     "EVP_DigestFinal failed: %s\n", eay_strerror());
		rc_vfree(res);
		res = 0;
	}
	EVP_MD_CTX_destroy(ctx);
	return res;
}

rc_vchar_t *
eay_md5_one(rc_vchar_t *data)
{
	caddr_t ctx;
	rc_vchar_t *res;

	ctx = eay_md5_init();
	eay_md5_update(ctx, data);
	res = eay_md5_final(ctx);

	return (res);
}

int
eay_md5_hashlen(void)
{
	return MD5_DIGEST_LENGTH << 3;
}

/*
 * eay_set_random
 *   size: number of bytes.
 */
rc_vchar_t *
eay_set_random(uint32_t size)
{
	rc_vchar_t *result;

	result = rc_vmalloc(size);
	if (!result)
		return 0;
	if (RAND_bytes((unsigned char *)result->v, result->l) != 1) {
#ifdef EAYDEBUG
		printf("failed to generate random number, code %lu\n",
		       ERR_get_error());
#else
		plog(PLOG_DEBUG, PLOGLOC, NULL,
		     "failed to generate random number, code %lu\n",
		     ERR_get_error());
#endif
		rc_vfree(result);
		return 0;
	}
	return result;
}

uint32_t
eay_random_uint32(void)
{
	uint32_t value;
	(void)RAND_bytes((uint8_t *)&value, sizeof(value));
	return value;
}

/* DH */
int
eay_dh_generate(rc_vchar_t *prime, uint32_t gg, unsigned int publen, rc_vchar_t **pub, rc_vchar_t **priv)
{
	BIGNUM *p = NULL, *g = NULL;
	const BIGNUM *pub_key, *priv_key;
	DH *dh = NULL;
	int error = -1;

	/* initialize */
	/* pre-process to generate number */
	if (eay_v2bn(&p, prime) < 0)
		goto end;

	if ((dh = DH_new()) == NULL)
		goto end;
	if ((g = BN_new()) == NULL)
		goto end;
	if (!BN_set_word(g, gg))
		goto end;

	if (!DH_set0_pqg(dh, p, NULL, g))
		goto end;
	g = p = NULL;

	if (publen != 0)
		DH_set_length(dh, publen);

	/* generate public and private number */
	if (!DH_generate_key(dh)) {
		/* OpenSSL 3 rejects a too-small exponent vs p (eaytest used 96). */
		if (publen == 0)
			goto end;
		DH_set_length(dh, 0);
		if (!DH_generate_key(dh))
			goto end;
	}

	DH_get0_key(dh, &pub_key, &priv_key);
	/* copy results to buffers */
	if (eay_bn2v(pub, pub_key) < 0)
		goto end;
	if (eay_bn2v(priv, priv_key) < 0) {
		rc_vfree(*pub);
		goto end;
	}

	error = 0;

      end:
	if (dh != NULL)
		DH_free(dh);
	if (p != NULL)
		BN_free(p);
	if (g != NULL)
		BN_free(g);
	return (error);
}

/* 0 iff 1 < r < p-1 (RFC 6989 s2.1) */
static int
eay_dh_pub_in_range(const BIGNUM *r, const BIGNUM *p)
{
	BIGNUM *pm1;
	int ok;

	if (r == NULL || p == NULL)
		return -1;
	if ((pm1 = BN_dup(p)) == NULL)
		return -1;
	ok = BN_sub_word(pm1, 1) && BN_cmp(r, BN_value_one()) > 0 &&
	    BN_cmp(r, pm1) < 0;
	BN_free(pm1);
	return ok ? 0 : -1;
}

int
eay_dh_compute (rc_vchar_t *prime, uint32_t gg, rc_vchar_t *pub,
		rc_vchar_t *priv, rc_vchar_t *pub2, rc_vchar_t **key)
{
	BIGNUM *dh_pub = NULL, *p = NULL, *g = NULL,
	    *pub_key = NULL, *priv_key = NULL;
	DH *dh = NULL;
	int l;
	unsigned char *v = NULL;
	int error = -1;

	/* make DH structure */
	if ((dh = DH_new()) == NULL)
		goto end;

	if (eay_v2bn(&p, prime) < 0)
		goto end;
	if ((g = BN_new()) == NULL)
		goto end;
	if (!BN_set_word(g, gg))
		goto end;
	if (!DH_set0_pqg(dh, p, NULL, g))
		goto end;
	p = NULL;
	g = NULL;

	if (eay_v2bn(&pub_key, pub) < 0)
		goto end;
	if (eay_v2bn(&priv_key, priv) < 0)
		goto end;
	if (!DH_set0_key(dh, pub_key, priv_key))
		goto end;
	pub_key = NULL;
	priv_key = NULL;

	DH_set_length(dh, pub2->l * 8);

	if ((v = racoon_calloc(prime->l, sizeof(unsigned char))) == NULL)
		goto end;

	/* make public number to compute */
	if (eay_v2bn(&dh_pub, pub2) < 0)
		goto end;

	/*
	 * RFC 6989 s2.1: the peer's public value r MUST satisfy
	 * 1 < r < p-1.  OpenSSL only rejects a degenerate shared secret,
	 * so a value >= p (e.g. p+2, which reduces to 2) would be used.
	 */
	if (eay_dh_pub_in_range(dh_pub, DH_get0_p(dh)) != 0) {
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
		    "peer DH public value out of range (RFC 6989)\n");
		goto end;
	}

	if ((l = DH_compute_key(v, dh_pub, dh)) == -1)
		goto end;
	memcpy((*key)->u + (prime->l - l), v, l);

	error = 0;

      end:
	if (dh_pub != NULL)
		BN_free(dh_pub);
	if (pub_key != NULL)
		BN_free(pub_key);
	if (priv_key != NULL)
		BN_free(priv_key);
	if (p != NULL)
		BN_free(p);
	if (g != NULL)
		BN_free(g);
	if (dh != NULL)
		DH_free(dh);
	if (v != NULL)
		racoon_free(v);
	return (error);
}

/* RFC 5903 group 19: P-256. KE is 64-byte x||y; shared secret is x (32). */
static int
ecp_curve_nid(size_t field_len)
{
	switch (field_len) {
	case 32:	/* P-256 */
		return NID_X9_62_prime256v1;
	case 48:	/* P-384 */
		return NID_secp384r1;
	case 66:	/* P-521 */
		return NID_secp521r1;
	default:
		return 0;
	}
}

int
eay_ecp_generate(size_t field_len, rc_vchar_t **pub, rc_vchar_t **priv)
{
	EC_KEY *ec = NULL;
	const EC_GROUP *grp;
	const EC_POINT *pt;
	const BIGNUM *priv_bn;
	unsigned char *buf = NULL;
	size_t n, publish;
	int nid;
	int error = -1;

	if (!pub || !priv)
		return -1;
	*pub = *priv = NULL;
	nid = ecp_curve_nid(field_len);
	if (nid == 0)
		return -1;
	publish = field_len * 2;	/* RFC 5903: x || y */
	buf = malloc(1 + publish);
	if (!buf)
		return -1;
	ec = EC_KEY_new_by_curve_name(nid);
	if (!ec || !EC_KEY_generate_key(ec))
		goto end;
	grp = EC_KEY_get0_group(ec);
	pt = EC_KEY_get0_public_key(ec);
	priv_bn = EC_KEY_get0_private_key(ec);
	if (!grp || !pt || !priv_bn)
		goto end;
	n = EC_POINT_point2oct(grp, pt, POINT_CONVERSION_UNCOMPRESSED,
	    buf, 1 + publish, NULL);
	if (n != 1 + publish || buf[0] != 0x04)
		goto end;
	*pub = rc_vnew(buf + 1, publish);
	*priv = rc_vmalloc(field_len);
	if (!*pub || !*priv)
		goto end;
	memset((*priv)->v, 0, field_len);
	if (BN_bn2binpad(priv_bn, (unsigned char *)(*priv)->v, field_len) !=
	    (int)field_len)
		goto end;
	error = 0;
      end:
	if (error) {
		if (*pub) {
			rc_vfree(*pub);
			*pub = NULL;
		}
		if (*priv) {
			rc_vfree(*priv);
			*priv = NULL;
		}
	}
	if (buf)
		free(buf);
	if (ec)
		EC_KEY_free(ec);
	return error;
}

int
eay_ecp_compute(size_t field_len, rc_vchar_t *pub, rc_vchar_t *priv,
    rc_vchar_t *pub_p, rc_vchar_t **key)
{
	EC_KEY *ec = NULL;
	EC_POINT *peer = NULL;
	const EC_GROUP *grp;
	BIGNUM *priv_bn = NULL;
	unsigned char *enc = NULL;
	int xlen;
	int nid;
	int error = -1;

	(void)pub;
	if (!priv || priv->l != field_len || !pub_p || pub_p->l != 2 * field_len ||
	    !key)
		return -1;
	nid = ecp_curve_nid(field_len);
	if (nid == 0)
		return -1;
	ec = EC_KEY_new_by_curve_name(nid);
	if (!ec)
		goto end;
	grp = EC_KEY_get0_group(ec);
	priv_bn = BN_bin2bn((unsigned char *)priv->v, field_len, NULL);
	if (!priv_bn || !EC_KEY_set_private_key(ec, priv_bn))
		goto end;
	enc = malloc(1 + 2 * field_len);
	if (!enc)
		goto end;
	enc[0] = 0x04;
	memcpy(enc + 1, pub_p->v, 2 * field_len);
	peer = EC_POINT_new(grp);
	if (!peer || !EC_POINT_oct2point(grp, peer, enc, 1 + 2 * field_len, NULL))
		goto end;
	if (!*key)
		*key = rc_vmalloc(field_len);
	if (!*key)
		goto end;
	xlen = ECDH_compute_key((*key)->v, field_len, peer, ec, NULL);
	if (xlen != (int)field_len)
		goto end;
	(*key)->l = field_len;
	error = 0;
      end:
	if (peer)
		EC_POINT_free(peer);
	if (priv_bn)
		BN_free(priv_bn);
	if (enc)
		free(enc);
	if (ec)
		EC_KEY_free(ec);
	return error;
}

int
eay_v2bn(BIGNUM **bn, rc_vchar_t *var)
{
	if ((*bn = BN_bin2bn((unsigned char *)var->v, var->l, NULL)) == NULL)
		return -1;

	return 0;
}

int
eay_bn2v(rc_vchar_t **var, const BIGNUM *bn)
{
	*var = rc_vmalloc(BN_num_bytes(bn));
	if (*var == NULL)
		return (-1);

	(*var)->l = BN_bn2bin(bn, (unsigned char *)(*var)->v);

	return 0;
}

const char *
eay_version(void)
{
	return SSLeay_version(SSLEAY_VERSION);
}

#ifdef SELFTEST
int
test_timegm(void)
{
	static struct {
		struct tm tm;
		time_t value;
	} testvec[] = {
		{ { 0, 0, 0, 2, 0, 70}, 86400},
		{ { 40, 46, 1, 9, 8, 101}, 1000000000},
		{ { 0, 0, 0, 1, 3, 105}, 1112313600},
	};
	int i;
	time_t result;
	int err = 0;

	for (i = 0; i < ARRAYLEN(testvec); ++i) {
		result = timegm(&testvec[i].tm);
		if (result != testvec[i].value) {
			plog(PLOG_INTERR, PLOGLOC, NULL,
			     "timegm selftest #%d failed (%ld != %ld)\n",
			     i, (long)result, (long)testvec[i].value);
			err = -1;
		}
	}
	return err;
}

int
test_utctime(void)
{
	static struct {
		time_t t;
		char *str;
	} testvec[] = {
		{ 86400, "700102000000Z"},
		{ 1000000000, "010909014640Z"},
		{ 1112313600, "050401000000Z"},
	};
	int i;
	struct timeval tv;
	ASN1_UTCTIME *utctime;
	int err = 0;

	for (i = 0; i < ARRAYLEN(testvec); ++i) {
		utctime = ASN1_UTCTIME_set(0, testvec[i].t);
		if (!utctime) {
			plog(PLOG_INTERR, PLOGLOC, NULL,
			     "utctime selftest #%d failed: ASN1_UTCTIME_set returned NULL\n",
			     i);
			err = -1;
			continue;
		}
		if (strncmp((char*)utctime->data, testvec[i].str, utctime->length) != 0) {
			plog(PLOG_INTERR, PLOGLOC, NULL,
			     "utctime selftest #%d failed: %.*s != %s\n",
			     i, (int)utctime->length, utctime->data,
			     testvec[i].str);
			err = -1;
		}
		if (eay_utctime(&tv, utctime) != 0 ||
		    tv.tv_sec != testvec[i].t) {
			plog(PLOG_INTERR, PLOGLOC, NULL,
			     "utctime selftest #%d failed (%ld != %ld, %s)\n",
			     i, (long)tv.tv_sec, (long)testvec[i].t, utctime->data);
			err = -1;
		}
		M_ASN1_UTCTIME_free(utctime);
	}
	return err;
}

int
test_generalizedtime(void)
{
	static struct {
		time_t t;
		char *str;
	} testvec[] = {
		{ 86400, "19700102000000Z"},
		{ 1000000000, "20010909014640Z"},
		{ 1112313600, "20050401000000Z"},
	};
	int i;
	struct timeval tv;
	ASN1_GENERALIZEDTIME *generalizedtime;
	int err = 0;

	for (i = 0; i < ARRAYLEN(testvec); ++i) {
		generalizedtime = ASN1_GENERALIZEDTIME_set(0, testvec[i].t);
		if (!generalizedtime) {
			plog(PLOG_INTERR, PLOGLOC, NULL,
			     "generalizedtime selftest #%d failed: ASN1_GENERALIZEDTIME_set returned NULL\n",
			     i);
			err = -1;
			continue;
		}
		if (strncmp((char*)generalizedtime->data, testvec[i].str,
		    generalizedtime->length) != 0) {
			plog(PLOG_INTERR, PLOGLOC, NULL,
			     "generalizedtime selftest #%d failed: %.*s != %s\n",
			     i, (int)generalizedtime->length,
			     generalizedtime->data, testvec[i].str);
			err = -1;
		}
		if (eay_generalizedtime(&tv, generalizedtime) != 0
		    || tv.tv_sec != testvec[i].t) {
			plog(PLOG_INTERR, PLOGLOC, NULL,
			     "generalizedtime selftest #%d failed (%ld != %ld, %s)\n",
			     i, (long)tv.tv_sec, (long)testvec[i].t, generalizedtime->data);
			err = -1;
		}
		M_ASN1_GENERALIZEDTIME_free(generalizedtime);
	}
	return err;
}

int
crypto_selftest(void)
{
	if (test_timegm() != 0)
		return -1;
	if (test_utctime() != 0)
		return -1;
	if (test_generalizedtime() != 0)
		return -1;
	return 0;
}
#endif

/*
 * Local Variables:
 * c-basic-offset: 8
 * End:
 */
