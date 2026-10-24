/*
 * r2dp control protocol (v1): the contract between a PF_KEY-like client
 * (the racoon2 shim) and a forwarder (DPDK app or the mock).
 *
 * Transport: AF_UNIX SOCK_SEQPACKET, one message per datagram, host
 * endian (local only).  Requests are answered by a completion carrying
 * the same type and seq.  EXPIRE/ACQUIRE are unsolicited forwarder->client.
 *
 * Nothing here depends on racoon2.  Algorithms are IANA IKEv2 transform
 * IDs, protocols are IP protocol numbers; the client translates.
 *
 * Layout rule: every struct is fixed-size with explicit padding and a
 * _Static_assert, so both sides can memcpy it.
 */
#ifndef R2DP_PROTO_H
#define R2DP_PROTO_H

#include <stdint.h>

#define R2DP_MAGIC        0x50443252u        /* "R2DP" little-endian */
#define R2DP_VERSION      1
#define R2DP_MAX_MSG      4096
#define R2DP_MAX_KEY      64                 /* per key blob, bytes */
#define R2DP_DEFAULT_SOCK "/run/r2dp/r2dp.sock"
#define R2DP_ENV_SOCK     "R2DP_SOCK"

enum r2dp_msg_type {
	R2DP_HELLO = 1,    /* c->f  struct r2dp_hello       */
	R2DP_HELLO_ACK,    /* f->c  struct r2dp_hello_ack   */
	R2DP_GETSPI,       /* c->f  struct r2dp_sa (+spi_min/max); reply fills spi */
	R2DP_SA_ADD,       /* struct r2dp_sa + enckey + authkey */
	R2DP_SA_UPDATE,    /* same; must follow GETSPI or exist */
	R2DP_SA_DEL,       /* key = spi + dst + proto           */
	R2DP_SA_GET,       /* key = spi + dst + proto           */
	R2DP_SP_ADD,       /* struct r2dp_sp (R2DP_SPF_UPDATE = upsert) */
	R2DP_SP_DEL,       /* by slid if nonzero, else dir+selector */
	R2DP_SP_GET,       /* by slid                            */
	R2DP_SP_DUMP,      /* reply: one SP_DUMP per policy, MORE until last */
	R2DP_EXPIRE,       /* f->c  struct r2dp_sa, .expired = 1 soft / 2 hard */
	R2DP_ACQUIRE,      /* f->c  struct r2dp_sa (provisional until M4) */
	R2DP_MSG_MAX
};

/* header flags */
#define R2DP_HF_MORE    0x1u   /* more messages follow for this seq (dump) */
#define R2DP_HF_NOKEYS  0x2u   /* SA message carries no key tail (default on completions) */

struct r2dp_hdr {
	uint32_t magic;
	uint16_t version;
	uint16_t type;     /* enum r2dp_msg_type */
	uint32_t len;      /* total bytes incl. header */
	uint32_t seq;      /* echoed in completions */
	uint32_t status;   /* errno-style, 0 = ok (completions only) */
	uint32_t flags;    /* R2DP_HF_* */
};
_Static_assert(sizeof(struct r2dp_hdr) == 24, "r2dp_hdr layout");

/* ---- addresses ------------------------------------------------------ */
#define R2DP_AF_UNSET 0
#define R2DP_AF_INET4 4
#define R2DP_AF_INET6 6

struct r2dp_addr {
	uint8_t  family;   /* R2DP_AF_*; UNSET => field not present */
	uint8_t  pad;
	uint16_t port;     /* network order, 0 = any */
	uint32_t scope;    /* IPv6 scope id */
	uint8_t  addr[16]; /* v4 uses addr[0..3] */
};
_Static_assert(sizeof(struct r2dp_addr) == 24, "r2dp_addr layout");

/* ---- shared constants (wire values, not racoon's) ------------------ */
#define R2DP_PROTO_ESP    50
#define R2DP_PROTO_AH     51
#define R2DP_PROTO_IPCOMP 108
#define R2DP_PROTO_ANY    255   /* selector ul_proto wildcard */

#define R2DP_MODE_TRANSPORT 1
#define R2DP_MODE_TUNNEL    2

#define R2DP_DIR_IN   1
#define R2DP_DIR_OUT  2
#define R2DP_DIR_FWD  3

#define R2DP_ACT_PROTECT 1
#define R2DP_ACT_DISCARD 2
#define R2DP_ACT_BYPASS  3

#define R2DP_LVL_REQUIRE 1
#define R2DP_LVL_USE     2
#define R2DP_LVL_UNIQUE  3

/* SP .protos bitmask (a policy may bundle several) */
#define R2DP_SPP_ESP     0x1
#define R2DP_SPP_AH      0x2
#define R2DP_SPP_IPCOMP  0x4

#define R2DP_NATT_NONE      0
#define R2DP_NATT_ESPINUDP  1

#define R2DP_SAF_ESN     0x1u   /* RFC 4303 extended sequence numbers */
#define R2DP_SPF_UPDATE  0x1u   /* SP_ADD: replace if selector exists */

/*
 * IANA IKEv2 ESP transform IDs used in .enc / .integ.
 * AEAD transforms (GCM/CCM/ChaCha20-Poly1305): .integ = 0 and the
 * enckey tail is cipher_key || 4-byte salt (RFC 4106/4309/7634).
 */
#define R2DP_ENCR_3DES        3
#define R2DP_ENCR_NULL        11
#define R2DP_ENCR_AES_CBC     12
#define R2DP_ENCR_AES_CTR     13
#define R2DP_ENCR_AES_CCM_8   14
#define R2DP_ENCR_AES_CCM_12  15
#define R2DP_ENCR_AES_CCM_16  16
#define R2DP_ENCR_AES_GCM_8   18
#define R2DP_ENCR_AES_GCM_12  19
#define R2DP_ENCR_AES_GCM_16  20
#define R2DP_ENCR_CHACHA20_POLY1305 28

#define R2DP_INTEG_NONE            0
#define R2DP_INTEG_HMAC_MD5_96     1
#define R2DP_INTEG_HMAC_SHA1_96    2
#define R2DP_INTEG_AES_XCBC_96     5
#define R2DP_INTEG_AES_CMAC_96     8
#define R2DP_INTEG_HMAC_SHA2_256_128 12
#define R2DP_INTEG_HMAC_SHA2_384_192 13
#define R2DP_INTEG_HMAC_SHA2_512_256 14

/* ---- HELLO ----------------------------------------------------------- */
#define R2DP_ROLE_UNSPEC 0
#define R2DP_ROLE_IKED   1
#define R2DP_ROLE_SPMD   2
#define R2DP_ROLE_CTL    3

struct r2dp_hello {
	uint32_t role;
	uint32_t pid;
	uint32_t reserved[2];
};
_Static_assert(sizeof(struct r2dp_hello) == 16, "r2dp_hello layout");

#define R2DP_FEAT_ESN     0x01u
#define R2DP_FEAT_NATT    0x02u
#define R2DP_FEAT_IPV6    0x04u
#define R2DP_FEAT_EXPIRE  0x08u
#define R2DP_FEAT_ACQUIRE 0x10u
#define R2DP_FEAT_INLINE  0x20u

struct r2dp_hello_ack {
	uint64_t epoch;          /* changes on forwarder restart: resync trigger */
	uint32_t max_msg;
	uint32_t features;       /* R2DP_FEAT_* */
	uint32_t enc_caps[8];    /* bit n = IANA encr transform n supported */
	uint32_t integ_caps[8];  /* bit n = IANA integ transform n supported */
};
_Static_assert(sizeof(struct r2dp_hello_ack) == 80, "r2dp_hello_ack layout");

/* ---- SA -------------------------------------------------------------- */
/*
 * Message = hdr + struct r2dp_sa + enckey[enckeylen] + authkey[authkeylen]
 * (tail absent when R2DP_HF_NOKEYS).  Lookup key for DEL/GET/UPDATE:
 * spi + dst + proto.
 */
struct r2dp_sa {
	uint64_t lft_hard_time, lft_hard_bytes;   /* 0 = infinite */
	uint64_t lft_soft_time, lft_soft_bytes;
	uint64_t cur_alloc, cur_add, cur_use, cur_bytes;   /* forwarder -> client */
	uint32_t spi;                 /* NETWORK byte order (as rcpfk_msg) */
	uint32_t reqid;
	uint32_t saflags;             /* R2DP_SAF_* */
	uint32_t spi_min, spi_max;    /* host order; GETSPI only, 0 = default */
	uint8_t  proto;               /* R2DP_PROTO_* */
	uint8_t  mode;                /* R2DP_MODE_* */
	uint8_t  enc;                 /* R2DP_ENCR_* */
	uint8_t  integ;               /* R2DP_INTEG_* */
	uint8_t  wsize;               /* replay window (packets), 0 = none */
	uint8_t  natt_type;           /* R2DP_NATT_* */
	uint8_t  expired;             /* EXPIRE only: 1 soft, 2 hard */
	uint8_t  pad0;
	uint16_t natt_sport, natt_dport;   /* network order; meaningful only if natt_type != NONE
	                                    * (iked sets them to 500 even for non-NAT-T SAs) */
	uint16_t enckeylen, authkeylen;    /* bytes of tail */
	uint32_t pad1;
	struct r2dp_addr src, dst;         /* tunnel endpoints */
	struct r2dp_addr natoa_src, natoa_dst;  /* UNSET if none */
};
_Static_assert(sizeof(struct r2dp_sa) == 200, "r2dp_sa layout");

/* ---- SP -------------------------------------------------------------- */
struct r2dp_sp {
	uint64_t lft_hard_time, lft_hard_bytes;
	uint32_t slid;                /* policy id; 0 on add => forwarder assigns */
	uint32_t reqid;
	uint32_t flags;               /* R2DP_SPF_* */
	uint32_t pad0;
	uint8_t  dir;                 /* R2DP_DIR_* */
	uint8_t  ul_proto;            /* IP proto or R2DP_PROTO_ANY */
	uint8_t  pref_src, pref_dst;  /* selector prefix lengths */
	uint8_t  action;              /* R2DP_ACT_* */
	uint8_t  mode;                /* R2DP_MODE_* */
	uint8_t  level;               /* R2DP_LVL_* */
	uint8_t  protos;              /* R2DP_SPP_* */
	char     tag[16];
	struct r2dp_addr sel_src, sel_dst;   /* selector (ports in addr.port) */
	struct r2dp_addr tun_src, tun_dst;   /* tunnel endpoints (tunnel mode) */
};
_Static_assert(sizeof(struct r2dp_sp) == 152, "r2dp_sp layout");

#endif /* R2DP_PROTO_H */
