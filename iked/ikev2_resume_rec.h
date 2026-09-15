/*
 * iked/ikev2_resume_rec.h — resume-dump record wire format.
 *
 * Pure record layer: the on-disk r2rs_sa layout plus helpers to
 * serialize fields into it and to validate a record read back from
 * disk.  No iked state, scheduling, or config dependencies — this
 * compiles standalone so resumetest can torture the format directly.
 *
 * v2 record (R2RS_VERSION 2): fixed-size packed struct.
 */
#ifndef IKEV2_RESUME_REC_H
#define IKEV2_RESUME_REC_H

#include <sys/types.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "vmbuf.h"	/* rc_vchar_t */

#define R2RS_MAGIC	0x52325253u	/* 'R2RS' */
#define R2RS_VERSION	2
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
	uint16_t encr_id;
	uint16_t integr_id;
	uint16_t encr_klen;
	uint8_t esn;
	uint8_t pad_c;
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

void r2rs_key_from_vchar(struct r2rs_key *, const rc_vchar_t *);
rc_vchar_t *r2rs_key_to_vchar(const struct r2rs_key *);
void r2rs_sa_to_wire(const struct sockaddr *, uint16_t *family,
    uint16_t *port, uint8_t addr[16]);
struct sockaddr *r2rs_wire_to_sa(uint16_t family, uint16_t port,
    const uint8_t addr[16]);
void r2rs_filename_in(char *buf, size_t buflen, const char *dir,
    const uint8_t i_ck[8], const uint8_t r_ck[8]);

/*
 * Validate a record as read back from disk.  Returns 0 when the
 * record is structurally sound, -1 otherwise.  Checks, in order:
 * magic/version, child count against the array bound, every key
 * length against R2RS_MAXKEY (a corrupt len field would otherwise
 * make r2rs_key_to_vchar read past its fixed-size data array), and
 * address family/port plausibility.
 */
int r2rs_validate(const struct r2rs_sa *);

#ifdef __cplusplus
}
#endif

#endif /* IKEV2_RESUME_REC_H */
