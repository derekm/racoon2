/* $Id: if_pfkeyv2.h,v 1.24 2008/02/06 05:49:40 mk Exp $ */

/*
 * Copyright (C) 2003 WIDE Project.
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

#include <sys/socket.h>
#ifdef HAVE_NET_PFKEYV2_H
# include <net/pfkeyv2.h>
#else
# include <stdint.h>
# include <linux/pfkeyv2.h>
#endif

#define RCPFK_ERRSTRBUFSIZE	128

/*
 * RFC 7296 §3.3.2 / RFC 4303 §2.2.1 ESN.
 * FreeBSD/OpenBSD/NetBSD pfkeyv2.h define SADB_X_SAFLAGS_ESN (0x400) as
 * a sadb_sa_flags bit (added to FreeBSD in r366755).  Linux has no
 * SADB SA-flags word, so the XFRM backend maps this portable bit onto
 * XFRM_STATE_ESN + XFRMA_REPLAY_ESN_VAL instead.  The portable value is
 * kept identical to the *BSD bit so a native header wins when present.
 */
#ifndef SADB_X_SAFLAGS_ESN
#define SADB_X_SAFLAGS_ESN	0x400
#endif
#define RCPFK_SOCKBUFSIZE	128 * 1024

/*
 * struct rcpfk_msg — the portable kernel-management (SAD/SPD) ABI, NOT the
 * PF_KEYv2 wire format despite the historical filename.
 *
 * This is a PF_KEY-shaped message container that the three XOR-compiled
 * backends all implement through the rcpfk_* entry points: lib/if_pfkeyv2.c
 * (*BSD PF_KEY), lib/if_xfrm.c (Linux NETLINK_XFRM), and lib/if_userspace.c
 * (loopback stub). The XFRM backend synthesizes the PF_KEY-isms
 * (spi/satype/samode/lifetimes); the userspace backend fakes them. Treat it
 * as a compatibility shim over kernel state, not as authoritative. The
 * XFRM-native concepts below (mark, if_id, device offload) have no PF_KEY
 * spelling; the *BSD and loopback backends ignore them. The `pfkey_*` names
 * in spmd are the legacy label for this same portable ABI, not a claim that
 * raw PF_KEYv2 is spoken.
 */
struct rcpfk_msg {
	int so;				/* KM fd: PF_KEY, NETLINK_XFRM, or userspace loopback */
	char estr[RCPFK_ERRSTRBUFSIZE];
	int eno;
	void *ptr;

	uint32_t seq;
	struct sockaddr *sa_src;
	struct sockaddr *sa_dst;
	struct sockaddr *sa2_src;   /* required for pfkey migrate */
	struct sockaddr *sa2_dst;   /* required for pfkey migrate */
	struct sockaddr *sa_natoa_src;
	struct sockaddr *sa_natoa_dst;
	uint32_t spi;
	uint32_t reqid;
	uint8_t satype;
	uint8_t samode;
	uint8_t enctype;
	uint8_t authtype;
	size_t enckeylen;
	size_t authkeylen;
	caddr_t enckey;
	caddr_t authkey;
	uint64_t lft_current_alloc;
	uint64_t lft_current_add;
	uint64_t lft_current_use;
	uint64_t lft_current_bytes;
	uint64_t lft_hard_time;
	uint64_t lft_hard_bytes;
	uint64_t lft_soft_time;
	uint64_t lft_soft_bytes;
	uint8_t expired;		/* 2:hard 1:soft */
	uint8_t wsize;
	uint32_t saflags;
	uint32_t flags;
#define PFK_FLAG_NOHARM		0x00000001
#define PFK_FLAG_DEBUG		0x00000002
#define PFK_FLAG_SEEADD		0x00000004
#define PFK_FLAG_NOPORTS	0x00000008
#define PFK_FLAG_EVENT		0x00000010
	/* rcpfk_handler(): consume messages until the reply to the request
	 * whose seq is rc->seq has been processed (or 5 s pass).  Other
	 * messages read meanwhile are dispatched with a scratch container,
	 * never parsed into rc.  For send-then-read callers (spmd). */
#define PFK_FLAG_WAITREPLY	0x00000020
	/* set on messages produced by a post-ENOBUFS resync dump */
#define PFK_FLAG_RESYNC		0x00000040

	uint32_t slid;			/* "spid" in KAME impl. */
	struct sockaddr *sp_src;
	struct sockaddr *sp_dst;
	uint8_t pref_src;
	uint8_t pref_dst;
	uint8_t ul_proto;
	uint8_t dir;
	uint8_t pltype;
	uint8_t ipsec_level;		/* always require in racoon2 */
	char tag_name[16];

	/* NAT-T: 0 = unset (derive from sa_* ports). Network byte order. */
	uint16_t natt_sport;
	uint16_t natt_dport;
	uint8_t natt_type;		/* 0 unset; Linux UDP_ENCAP_ESPINUDP */

	/* --- XFRM-native policy/offload (Linux NETLINK_XFRM only). *BSD
	 * PF_KEY and the loopback userspace backend have no equivalent and
	 * ignore these; 0/"" = unset. These are the features XFRM supports
	 * that PF_KEY has no spelling for. Set by the config/grammar layer;
	 * emitted by the XFRM backend (lib/if_xfrm.c) as XFRMA_MARK,
	 * XFRMA_IF_ID and XFRMA_OFFLOAD_DEV. --- */
	uint32_t mark;			/* XFRMA_MARK value (honored with mark_mask) */
	uint32_t mark_mask;		/* XFRMA_MARK mask; non-zero => emit */
	uint32_t if_id;			/* XFRMA_IF_ID: per-SA/policy interface/VRF */
	uint32_t offload_ifindex;	/* XFRMA_OFFLOAD_DEV: device ifindex */
	uint8_t offload_flags;		/* XFRM_OFFLOAD_* (direction) or 0 = unset */
	char offload_ifname[16];	/* offload device name; resolved to ifindex at send */

	/* internal buffers; no need to touch from external */
	struct sockaddr_storage sa_src_storage;
	struct sockaddr_storage sa_dst_storage;
	struct sockaddr_storage sa2_src_storage; /* required for pfkey migrate */
	struct sockaddr_storage sa2_dst_storage; /* required for pfkey migrate */
	struct sockaddr_storage sp_src_storage;
	struct sockaddr_storage sp_dst_storage;
	struct sockaddr_storage sa_natoa_src_storage;
	struct sockaddr_storage sa_natoa_dst_storage;
};

struct rcpfk_cb {
	int (*cb_getspi) (struct rcpfk_msg *);
	int (*cb_update) (struct rcpfk_msg *);
	int (*cb_add) (struct rcpfk_msg *);
	int (*cb_expire) (struct rcpfk_msg *);
	int (*cb_acquire) (struct rcpfk_msg *);
	int (*cb_delete) (struct rcpfk_msg *);
	int (*cb_get) (struct rcpfk_msg *);
	int (*cb_spdupdate) (struct rcpfk_msg *);
	int (*cb_spdadd) (struct rcpfk_msg *);
	int (*cb_spddelete) (struct rcpfk_msg *);
	int (*cb_spddelete2) (struct rcpfk_msg *);
	int (*cb_spdexpire) (struct rcpfk_msg *);
	int (*cb_spdget) (struct rcpfk_msg *);
	int (*cb_spddump) (struct rcpfk_msg *);
#ifdef SADB_X_MIGRATE
	int (*cb_migrate) (struct rcpfk_msg *);
#endif
	/*
	 * Optional (NULL = ignored).  XFRM backend only for now.
	 *
	 * cb_mapping: the kernel saw an authenticated ESP-in-UDP packet for
	 *   the inbound SA rc->spi (dst rc->sa_dst) arrive from a new NAT
	 *   mapping.  rc->sa_src is the old peer address:port, rc->sa2_src
	 *   the new one (XFRM_MSG_MAPPING, XFRMNLGRP_MAPPING).
	 * cb_sadump: one SA from a resync dump (flags has PFK_FLAG_RESYNC).
	 * cb_resync: a notification overflow (ENOBUFS) was recovered from;
	 *   the SPD (cb_spddump) and SAD (cb_sadump) dumps that preceded
	 *   this call describe the kernel state now.  rc->eno = ENOBUFS.
	 */
	int (*cb_mapping) (struct rcpfk_msg *);
	int (*cb_sadump) (struct rcpfk_msg *);
	int (*cb_resync) (struct rcpfk_msg *);
};

extern int rcpfk_handler (struct rcpfk_msg *);
extern int rcpfk_init (struct rcpfk_msg *, struct rcpfk_cb *);
extern int rcpfk_clean (struct rcpfk_msg *);
extern int rcpfk_send_getspi (struct rcpfk_msg *);
extern int rcpfk_send_update (struct rcpfk_msg *);
extern int rcpfk_send_add (struct rcpfk_msg *);
extern int rcpfk_send_delete (struct rcpfk_msg *);
extern int rcpfk_send_get (struct rcpfk_msg *);
extern int rcpfk_send_acquire (struct rcpfk_msg *);
extern int rcpfk_send_register (struct rcpfk_msg *);
extern int rcpfk_send_spdupdate (struct rcpfk_msg *);
extern int rcpfk_send_spdadd (struct rcpfk_msg *);
extern int rcpfk_send_spddelete (struct rcpfk_msg *);
extern int rcpfk_send_spddelete2 (struct rcpfk_msg *);
extern int rcpfk_send_spdget (struct rcpfk_msg *);
extern int rcpfk_send_spddump (struct rcpfk_msg *rc);
extern int rcpfk_send_migrate (struct rcpfk_msg *rc);
extern int rcpfk_supported_auth (int);
extern int rcpfk_supported_enc (int);
