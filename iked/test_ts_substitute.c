#include "config.h"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "racoon.h"
#include "var.h"
#include "plog.h"
#include "sockmisc.h"

#include "isakmp.h"
#include "oakley.h"
#include "ikev2.h"
#include "isakmp_impl.h"
#include "ikev2_impl.h"
#include "ike_conf.h"

#include <getopt.h>

#include "test_util.h"

TEST_MAIN_STUBS()

#define TS_I_ADDR4      "10.0.0.1"
#define TS_R_ADDR4      "10.0.0.2"
#define TS_RANGE_END4   "10.0.0.255"

#define TS_I_ADDR6      "fd00::1"
#define TS_R_ADDR6      "fd00::2"

#define LOCAL4_ADDR     "203.0.113.10"
#define REMOTE4_ADDR    "198.51.100.20"
#define LOCAL6_ADDR     "2001:db8::10"
#define REMOTE6_ADDR    "2001:db8::20"

#define SA_PORT         4500

/* Writes binary IPv4 or IPv6 address bytes into dst depending on TS type */
static void
ts_pton(uint8_t *dst, uint8_t ts_type, const char *s)
{
	struct in_addr a4;
	struct in6_addr a6;

	if (ts_type == IKEV2_TS_IPV6_ADDR_RANGE) {
		test_pton6(s, &a6);
		memcpy(dst, &a6, sizeof(a6));
	} else {
		test_pton4(s, &a4);
		memcpy(dst, &a4, sizeof(a4));
	}
}

static rc_vchar_t *
make_ts_payload(uint8_t ts_type, const char *start_addr, const char *end_addr)
{
	rc_vchar_t *v;
	struct ikev2payl_traffic_selector *payl;
	struct ikev2_traffic_selector *ts;
	size_t addrlen;
	uint8_t *addr;
	size_t len;

	addrlen = (ts_type == IKEV2_TS_IPV6_ADDR_RANGE) ? sizeof(struct in6_addr)
	                                                : sizeof(struct in_addr);
	len = sizeof(*payl) + sizeof(*ts) + 2 * addrlen;

	v = rc_vmalloc(len);
	if (v == NULL)
		exit(1);
	memset(v->v, 0, v->l);

	payl = (struct ikev2payl_traffic_selector *)v->v;
	payl->header.payload_length = htons((uint16_t)len);
	payl->tsh.num_ts = 1;

	ts = (struct ikev2_traffic_selector *)(payl + 1);
	ts->ts_type = ts_type;
	ts->selector_length = htons((uint16_t)(sizeof(*ts) + 2 * addrlen));
	ts->protocol_id = IKEV2_TS_PROTO_ANY;
	ts->start_port = htons(IKEV2_TS_PORT_MIN);
	ts->end_port = htons(IKEV2_TS_PORT_MAX);

	addr = (uint8_t *)(ts + 1);
	ts_pton(addr, ts_type, start_addr);
	ts_pton(addr + addrlen, ts_type, end_addr);

	return v;
}

static int
ts_addr_is(rc_vchar_t *v, const char *expect_start, const char *expect_end)
{
	struct ikev2payl_traffic_selector *payl = v->v;
	struct ikev2_traffic_selector *ts = (struct ikev2_traffic_selector *)
	    ((uint8_t *)v->v + sizeof(*payl));
	size_t addrlen = (ts->ts_type == IKEV2_TS_IPV6_ADDR_RANGE)
	    ? sizeof(struct in6_addr) : sizeof(struct in_addr);
	uint8_t *addr = (uint8_t *)(ts + 1);
	uint8_t expect[2 * sizeof(struct in6_addr)];

	ts_pton(expect, ts->ts_type, expect_start);
	ts_pton(expect + addrlen, ts->ts_type, expect_end);

	return memcmp(addr, expect, 2 * addrlen) == 0;
}

struct ts_fixture {
	struct ikev2_child_sa child;
	struct ikev2_sa parent;
	struct rcf_selector selector;
	struct rcf_policy policy;
	struct sockaddr_storage local, remote;
	rc_vchar_t *ts_i;
	rc_vchar_t *ts_r;
};

static void
fixture_init(struct ts_fixture *f, int is_initiator, int transport,
    int behind_nat, int peer_behind_nat, int family, uint8_t ts_type,
    const char *ts_i_addr, const char *ts_r_addr)
{
	memset(f, 0, sizeof(*f));

	if (family == AF_INET) {
		test_make_addr4(&f->local, LOCAL4_ADDR, SA_PORT);
		test_make_addr4(&f->remote, REMOTE4_ADDR, SA_PORT);
	} else {
		test_make_addr6(&f->local, LOCAL6_ADDR, SA_PORT);
		test_make_addr6(&f->remote, REMOTE6_ADDR, SA_PORT);
	}

	f->parent.is_initiator = is_initiator;
	f->parent.local = (struct sockaddr *)&f->local;
	f->parent.remote = (struct sockaddr *)&f->remote;
	f->parent.behind_nat = behind_nat;
	f->parent.peer_behind_nat = peer_behind_nat;

	f->policy.ipsec_mode = transport ? RCT_IPSM_TRANSPORT : RCT_IPSM_TUNNEL;
	f->selector.pl = &f->policy;

	f->child.is_initiator = is_initiator;
	f->child.parent = &f->parent;
	f->child.selector = &f->selector;
	f->child.child_param.use_transport_mode = transport;

	f->ts_i = make_ts_payload(ts_type, ts_i_addr, ts_i_addr);
	f->ts_r = make_ts_payload(ts_type, ts_r_addr, ts_r_addr);
}

static void
fixture_init_v4(struct ts_fixture *f, int is_initiator, int transport,
    int behind_nat, int peer_behind_nat)
{
	fixture_init(f, is_initiator, transport, behind_nat, peer_behind_nat,
	    AF_INET, IKEV2_TS_IPV4_ADDR_RANGE, TS_I_ADDR4, TS_R_ADDR4);
}

static void
fixture_free(struct ts_fixture *f)
{
	rc_vfree(f->ts_i);
	rc_vfree(f->ts_r);
	if (f->parent.oa_i)
		rc_free(f->parent.oa_i);
	if (f->parent.oa_r)
		rc_free(f->parent.oa_r);
}

static struct ikev2_payload_header *
ts_payl(rc_vchar_t *v)
{
	return (struct ikev2_payload_header *)v->v;
}

static void
run_ts_case(int is_initiator, int transport, int behind_nat,
    int peer_behind_nat, int family, uint8_t ts_type,
    const char *ts_i_addr, const char *ts_r_addr,
    void (*fixup)(struct ts_fixture *),
    int expect_rc, const char *expect_i, const char *expect_r)
{
	struct ts_fixture f;

	fixture_init(&f, is_initiator, transport, behind_nat, peer_behind_nat,
	    family, ts_type, ts_i_addr, ts_r_addr);
	if (fixup != NULL)
		fixup(&f);
	TEST_CHECK(ikev2_addr_substitute(&f.child, ts_payl(f.ts_i),
	    ts_payl(f.ts_r)) == expect_rc);
	if (expect_i != NULL)
		TEST_CHECK(ts_addr_is(f.ts_i, expect_i, expect_i));
	if (expect_r != NULL)
		TEST_CHECK(ts_addr_is(f.ts_r, expect_r, expect_r));
	fixture_free(&f);
}

static void
run_ts_case_v4(int is_initiator, int transport, int behind_nat,
    int peer_behind_nat, void (*fixup)(struct ts_fixture *),
    int expect_rc, const char *expect_i, const char *expect_r)
{
	run_ts_case(is_initiator, transport, behind_nat, peer_behind_nat,
	    AF_INET, IKEV2_TS_IPV4_ADDR_RANGE, TS_I_ADDR4, TS_R_ADDR4,
	    fixup, expect_rc, expect_i, expect_r);
}

static void
fixup_drop_selector(struct ts_fixture *f)
{
	f->child.selector = NULL;
}

static void
fixup_drop_policy(struct ts_fixture *f)
{
	f->selector.pl = NULL;
}

static void
test_no_nat_leaves_ts_alone(void)
{
	run_ts_case_v4(TRUE, TRUE, FALSE, FALSE, NULL, 0,
	    TS_I_ADDR4, TS_R_ADDR4);
}

static void
test_initiator_transport_substitutes(void)
{
	/* Both NATed → both TSs rewritten. */
	run_ts_case_v4(TRUE, TRUE, TRUE, TRUE, NULL, 0,
	    LOCAL4_ADDR, REMOTE4_ADDR);
	/* Only we (initiator) NATed → TSi only. */
	run_ts_case_v4(TRUE, TRUE, TRUE, FALSE, NULL, 0,
	    LOCAL4_ADDR, TS_R_ADDR4);
	/* Only peer (responder) NATed → TSr only. */
	run_ts_case_v4(TRUE, TRUE, FALSE, TRUE, NULL, 0,
	    TS_I_ADDR4, REMOTE4_ADDR);
}

/*
 * CREATE_CHILD_SA started by the IKE RESPONDER (e.g. its rekey after a lost
 * inbound SA): the NATed IKE initiator answers it, so in this exchange it
 * is the responder and the NATed party is TSr.  Roles follow the child
 * exchange (child.is_initiator), not the IKE SA.
 */
static void
fixup_child_responder(struct ts_fixture *f)
{
	f->child.is_initiator = FALSE;
}

static void
fixup_child_initiator(struct ts_fixture *f)
{
	f->child.is_initiator = TRUE;
}

static void
test_rekey_started_by_ike_responder(void)
{
	/* NATed IKE initiator answers: TSr <- its own address, TSi kept */
	run_ts_case_v4(TRUE, TRUE, TRUE, FALSE, fixup_child_responder, 0,
	    TS_I_ADDR4, LOCAL4_ADDR);
	/* IKE responder starts it, its peer (IKE initiator) NATed: TSr <- peer */
	run_ts_case_v4(FALSE, TRUE, FALSE, TRUE, fixup_child_initiator, 0,
	    TS_I_ADDR4, REMOTE4_ADDR);
}

static void
test_responder_transport_substitutes(void)
{
	/* Both NATed → TSi←remote, TSr←local. */
	run_ts_case_v4(FALSE, TRUE, TRUE, TRUE, NULL, 0,
	    REMOTE4_ADDR, LOCAL4_ADDR);
	/* Only peer (initiator) NATed → TSi only. */
	run_ts_case_v4(FALSE, TRUE, FALSE, TRUE, NULL, 0,
	    REMOTE4_ADDR, TS_R_ADDR4);
	/* Only we (responder) NATed → TSr only. */
	run_ts_case_v4(FALSE, TRUE, TRUE, FALSE, NULL, 0,
	    TS_I_ADDR4, LOCAL4_ADDR);

	run_ts_case_v4(FALSE, TRUE, TRUE, TRUE, fixup_drop_selector, 0,
	    REMOTE4_ADDR, NULL);
}

static void
test_tunnel_mode_untouched(void)
{
	run_ts_case_v4(TRUE, FALSE, TRUE, TRUE, NULL, 0,
	    TS_I_ADDR4, TS_R_ADDR4);

	run_ts_case_v4(FALSE, FALSE, TRUE, TRUE, NULL, 0,
	    TS_I_ADDR4, TS_R_ADDR4);
}

static void
test_initiator_without_selector_untouched(void)
{
	run_ts_case_v4(TRUE, TRUE, TRUE, TRUE, fixup_drop_selector, 0,
	    TS_I_ADDR4, NULL);
}

static void
test_already_matching_ts_untouched(void)
{
	run_ts_case(TRUE, TRUE, TRUE, TRUE, AF_INET,
	    IKEV2_TS_IPV4_ADDR_RANGE, LOCAL4_ADDR, REMOTE4_ADDR,
	    NULL, 0, LOCAL4_ADDR, REMOTE4_ADDR);
}

static void
test_ipv6_transport_substitutes(void)
{
	run_ts_case(TRUE, TRUE, TRUE, TRUE, AF_INET6,
	    IKEV2_TS_IPV6_ADDR_RANGE, TS_I_ADDR6, TS_R_ADDR6,
	    NULL, 0, LOCAL6_ADDR, REMOTE6_ADDR);
}

static void
fixup_range_ts_i(struct ts_fixture *f)
{
	rc_vfree(f->ts_i);
	f->ts_i = make_ts_payload(IKEV2_TS_IPV4_ADDR_RANGE, TS_I_ADDR4,
	    TS_RANGE_END4);
}

static void
fixup_range_ts_r(struct ts_fixture *f)
{
	rc_vfree(f->ts_r);
	f->ts_r = make_ts_payload(IKEV2_TS_IPV4_ADDR_RANGE, TS_R_ADDR4,
	    TS_RANGE_END4);
}

static void
test_range_ts_not_substituted(void)
{
	struct ts_fixture f;

	fixture_init(&f, TRUE, TRUE, TRUE, TRUE, AF_INET,
	    IKEV2_TS_IPV4_ADDR_RANGE, LOCAL4_ADDR, REMOTE4_ADDR);
	fixup_range_ts_i(&f);
	TEST_CHECK(ikev2_addr_substitute(&f.child, ts_payl(f.ts_i),
	    ts_payl(f.ts_r)) == -1);
	TEST_CHECK(ts_addr_is(f.ts_i, TS_I_ADDR4, TS_RANGE_END4));
	TEST_CHECK(ts_addr_is(f.ts_r, REMOTE4_ADDR, REMOTE4_ADDR));
	fixture_free(&f);

	fixture_init(&f, TRUE, TRUE, TRUE, TRUE, AF_INET,
	    IKEV2_TS_IPV4_ADDR_RANGE, TS_I_ADDR4, TS_R_ADDR4);
	fixup_range_ts_r(&f);
	TEST_CHECK(ikev2_addr_substitute(&f.child, ts_payl(f.ts_i),
	    ts_payl(f.ts_r)) == -1);
	TEST_CHECK(ts_addr_is(f.ts_i, LOCAL4_ADDR, LOCAL4_ADDR));
	TEST_CHECK(ts_addr_is(f.ts_r, TS_R_ADDR4, TS_RANGE_END4));
	fixture_free(&f);
}

static void
test_invalid_ts_type_untouched(void)
{
	struct ts_fixture f;

	fixture_init(&f, TRUE, TRUE, TRUE, TRUE, AF_INET,
	    IKEV2_TS_FC_ADDR_RANGE, TS_I_ADDR4, TS_R_ADDR4);
	TEST_CHECK(ikev2_addr_substitute(&f.child, ts_payl(f.ts_i),
	    ts_payl(f.ts_r)) == -1);
	TEST_CHECK(((struct ikev2payl_traffic_selector *)f.ts_i->v)->tsh.num_ts
	    == 1);
	fixture_free(&f);
}

static void
test_selector_without_policy_untouched(void)
{
	run_ts_case_v4(TRUE, TRUE, TRUE, TRUE, fixup_drop_policy, 0,
	    TS_I_ADDR4, TS_R_ADDR4);
}

/* Build a TS payload with n single-address entries of addr (n may be 0). */
static rc_vchar_t *
make_ts_payload_n(uint8_t ts_type, int n, const char *addr)
{
	rc_vchar_t *v;
	struct ikev2payl_traffic_selector *payl;
	size_t addrlen, one, len;
	int i;

	addrlen = (ts_type == IKEV2_TS_IPV6_ADDR_RANGE) ? sizeof(struct in6_addr)
	                                                : sizeof(struct in_addr);
	one = sizeof(struct ikev2_traffic_selector) + 2 * addrlen;
	len = sizeof(*payl) + (size_t)n * one;
	v = rc_vmalloc(len);	/* exact size: ASan sees any read past it */
	if (v == NULL)
		exit(1);
	memset(v->v, 0, v->l);
	payl = (struct ikev2payl_traffic_selector *)v->v;
	payl->header.payload_length = htons((uint16_t)len);
	payl->tsh.num_ts = (uint8_t)n;
	for (i = 0; i < n; i++) {
		struct ikev2_traffic_selector *ts = (struct ikev2_traffic_selector *)
		    ((uint8_t *)(payl + 1) + (size_t)i * one);
		uint8_t *a = (uint8_t *)(ts + 1);

		ts->ts_type = ts_type;
		ts->selector_length = htons((uint16_t)one);
		ts->protocol_id = IKEV2_TS_PROTO_ANY;
		ts->start_port = htons(IKEV2_TS_PORT_MIN);
		ts->end_port = htons(IKEV2_TS_PORT_MAX);
		ts_pton(a, ts_type, addr);
		ts_pton(a + addrlen, ts_type, addr);
	}
	return v;
}

/* Does TS entry k (single-address entries of equal size) carry addr? */
static int
ts_entry_is(rc_vchar_t *v, int k, const char *addr)
{
	struct ikev2_traffic_selector *ts0 = (struct ikev2_traffic_selector *)
	    ((uint8_t *)v->v + sizeof(struct ikev2payl_traffic_selector));
	size_t addrlen = (ts0->ts_type == IKEV2_TS_IPV6_ADDR_RANGE)
	    ? sizeof(struct in6_addr) : sizeof(struct in_addr);
	size_t one = sizeof(*ts0) + 2 * addrlen;
	uint8_t *a = (uint8_t *)(ts0 + 1) + (size_t)k * one;
	uint8_t expect[sizeof(struct in6_addr)];

	ts_pton(expect, ts0->ts_type, addr);
	return memcmp(a, expect, addrlen) == 0 &&
	    memcmp(a + addrlen, expect, addrlen) == 0;
}

/* Every TS entry is substituted, not only the first (RFC 7296 2.23.1). */
static void
test_all_ts_entries_substituted(void)
{
	struct ts_fixture f;

	fixture_init_v4(&f, TRUE, TRUE, TRUE, TRUE);
	rc_vfree(f.ts_i);
	rc_vfree(f.ts_r);
	f.ts_i = make_ts_payload_n(IKEV2_TS_IPV4_ADDR_RANGE, 3, TS_I_ADDR4);
	f.ts_r = make_ts_payload_n(IKEV2_TS_IPV4_ADDR_RANGE, 2, TS_R_ADDR4);
	TEST_CHECK(ikev2_addr_substitute(&f.child, ts_payl(f.ts_i),
	    ts_payl(f.ts_r)) == 0);
	TEST_CHECK(ts_entry_is(f.ts_i, 0, LOCAL4_ADDR));
	TEST_CHECK(ts_entry_is(f.ts_i, 1, LOCAL4_ADDR));
	TEST_CHECK(ts_entry_is(f.ts_i, 2, LOCAL4_ADDR));
	TEST_CHECK(ts_entry_is(f.ts_r, 0, REMOTE4_ADDR));
	TEST_CHECK(ts_entry_is(f.ts_r, 1, REMOTE4_ADDR));
	fixture_free(&f);
}

/*
 * An IPv6 TS over an IPv4 IKE SA must be left alone, and must not read
 * 16 address bytes out of a 16-byte sockaddr_in.  The IKE SA endpoints
 * are exact-size heap copies (as iked's are), so ASan builds catch it.
 */
static void
test_family_mismatch_untouched(void)
{
	struct ts_fixture f;
	struct sockaddr *hl, *hr;

	fixture_init(&f, FALSE, TRUE, TRUE, TRUE, AF_INET,
	    IKEV2_TS_IPV6_ADDR_RANGE, TS_I_ADDR6, TS_R_ADDR6);
	hl = rcs_sadup((struct sockaddr *)&f.local);
	hr = rcs_sadup((struct sockaddr *)&f.remote);
	if (hl == NULL || hr == NULL)
		exit(1);
	f.parent.local = hl;
	f.parent.remote = hr;
	TEST_CHECK(ikev2_addr_substitute(&f.child, ts_payl(f.ts_i),
	    ts_payl(f.ts_r)) == 0);
	TEST_CHECK(ts_addr_is(f.ts_i, TS_I_ADDR6, TS_I_ADDR6));
	TEST_CHECK(ts_addr_is(f.ts_r, TS_R_ADDR6, TS_R_ADDR6));
	rc_free(hl);
	rc_free(hr);
	fixture_free(&f);
}

/* num_ts = 0 passes ikev2_check_ts_payload(); it must not be read. */
static void
test_num_ts_zero_rejected(void)
{
	struct ts_fixture f;

	fixture_init_v4(&f, FALSE, TRUE, TRUE, TRUE);
	rc_vfree(f.ts_i);
	f.ts_i = make_ts_payload_n(IKEV2_TS_IPV4_ADDR_RANGE, 0, TS_I_ADDR4);
	TEST_CHECK(ikev2_addr_substitute(&f.child, ts_payl(f.ts_i),
	    ts_payl(f.ts_r)) == -1);
	TEST_CHECK(ts_addr_is(f.ts_r, TS_R_ADDR4, TS_R_ADDR4));
	fixture_free(&f);
}

/* A num_ts that overruns the payload length is rejected, not walked. */
static void
test_overrunning_num_ts_rejected(void)
{
	struct ts_fixture f;

	fixture_init_v4(&f, FALSE, TRUE, TRUE, TRUE);
	((struct ikev2payl_traffic_selector *)f.ts_i->v)->tsh.num_ts = 2;
	TEST_CHECK(ikev2_addr_substitute(&f.child, ts_payl(f.ts_i),
	    ts_payl(f.ts_r)) == -1);
	fixture_free(&f);
}

/* A child without a parent IKE SA is an error, not a NULL dereference. */
static void
test_no_parent_rejected(void)
{
	struct ts_fixture f;

	fixture_init_v4(&f, TRUE, TRUE, TRUE, TRUE);
	f.child.parent = NULL;
	TEST_CHECK(ikev2_addr_substitute(&f.child, ts_payl(f.ts_i),
	    ts_payl(f.ts_r)) == -1);
	TEST_CHECK(ts_addr_is(f.ts_i, TS_I_ADDR4, TS_I_ADDR4));
	fixture_free(&f);
}


/* N3: RFC 7296 §2.23.1 per-side substitution — only the NATed party's TS. */
static void
test_per_side_nat_substitution(void)
{
	/* responder, peer behind NAT only */
	run_ts_case_v4(FALSE, TRUE, FALSE, TRUE, NULL, 0,
	    REMOTE4_ADDR, TS_R_ADDR4);
	/* responder, self behind NAT only */
	run_ts_case_v4(FALSE, TRUE, TRUE, FALSE, NULL, 0,
	    TS_I_ADDR4, LOCAL4_ADDR);
	/* initiator, self behind NAT only */
	run_ts_case_v4(TRUE, TRUE, TRUE, FALSE, NULL, 0,
	    LOCAL4_ADDR, TS_R_ADDR4);
	/* initiator, peer behind NAT only */
	run_ts_case_v4(TRUE, TRUE, FALSE, TRUE, NULL, 0,
	    TS_I_ADDR4, REMOTE4_ADDR);
}
static void
test_null_args(void)
{
	struct ts_fixture f;

	fixture_init_v4(&f, TRUE, TRUE, TRUE, TRUE);

	TEST_CHECK(ikev2_addr_substitute(NULL, ts_payl(f.ts_i),
	    ts_payl(f.ts_r)) == -1);
	TEST_CHECK(ikev2_addr_substitute(&f.child, NULL,
	    ts_payl(f.ts_r)) == -1);
	TEST_CHECK(ikev2_addr_substitute(&f.child, ts_payl(f.ts_i),
	    NULL) == -1);

	TEST_CHECK(ts_addr_is(f.ts_i, TS_I_ADDR4, TS_I_ADDR4));
	TEST_CHECK(ts_addr_is(f.ts_r, TS_R_ADDR4, TS_R_ADDR4));
	fixture_free(&f);
}

static int
oa_is(struct sockaddr *sa, const char *expect)
{
	struct in_addr a4;

	if (sa == NULL || sa->sa_family != AF_INET)
		return 0;
	test_pton4(expect, &a4);
	return memcmp(&((struct sockaddr_in *)sa)->sin_addr, &a4,
	    sizeof(a4)) == 0;
}

/*
 * N4 (RFC 3948 s3.1.2, RFC 7296 s2.23.1): oa_i/oa_r are the ORIGINAL
 * addresses carried in the received TS payloads, before substitution, on
 * BOTH roles.  The receiver of a transport-mode ESP-in-UDP packet fixes
 * the TCP/UDP checksum from the address the sender used (the TS it sent)
 * to the address on the wire, so the initiator's OA for its own side is
 * the post-NAT TSi the responder narrowed to, never its local address.
 */
static void
test_natoa_originals(void)
{
	struct ts_fixture f;

	/* responder, initiator NATed: oa_i = proposed TSi, oa_r unset */
	fixture_init_v4(&f, FALSE, TRUE, FALSE, TRUE);
	TEST_CHECK(ikev2_addr_substitute(&f.child, ts_payl(f.ts_i),
	    ts_payl(f.ts_r)) == 0);
	TEST_CHECK(oa_is(f.parent.oa_i, TS_I_ADDR4));
	TEST_CHECK(f.parent.oa_r == NULL);
	fixture_free(&f);

	/* initiator behind NAT: oa_i = received TSi, NOT the local addr */
	fixture_init_v4(&f, TRUE, TRUE, TRUE, FALSE);
	TEST_CHECK(ikev2_addr_substitute(&f.child, ts_payl(f.ts_i),
	    ts_payl(f.ts_r)) == 0);
	TEST_CHECK(oa_is(f.parent.oa_i, TS_I_ADDR4));
	TEST_CHECK(!oa_is(f.parent.oa_i, LOCAL4_ADDR));
	TEST_CHECK(f.parent.oa_r == NULL);
	fixture_free(&f);

	/* both NATed, initiator: oa_r = received TSr, not the remote addr */
	fixture_init_v4(&f, TRUE, TRUE, TRUE, TRUE);
	TEST_CHECK(ikev2_addr_substitute(&f.child, ts_payl(f.ts_i),
	    ts_payl(f.ts_r)) == 0);
	TEST_CHECK(oa_is(f.parent.oa_i, TS_I_ADDR4));
	TEST_CHECK(oa_is(f.parent.oa_r, TS_R_ADDR4));
	fixture_free(&f);

	/* both NATed, responder: oa_i/oa_r = proposed TSi/TSr, never the
	 * SA endpoints (an OA equal to the endpoint is dropped by FreeBSD
	 * key_setnatt and disables the TCP checksum check) */
	fixture_init_v4(&f, FALSE, TRUE, TRUE, TRUE);
	TEST_CHECK(ikev2_addr_substitute(&f.child, ts_payl(f.ts_i),
	    ts_payl(f.ts_r)) == 0);
	TEST_CHECK(oa_is(f.parent.oa_i, TS_I_ADDR4));
	TEST_CHECK(oa_is(f.parent.oa_r, TS_R_ADDR4));
	TEST_CHECK(!oa_is(f.parent.oa_i, REMOTE4_ADDR));
	TEST_CHECK(!oa_is(f.parent.oa_r, LOCAL4_ADDR));
	fixture_free(&f);
}

/* A range TS has no single original address: the OA stays unset rather
 * than taking the range start (0.0.0.0 for a wildcard) as a bogus OA. */
static void
test_natoa_range_unset(void)
{
	struct ts_fixture f;

	fixture_init_v4(&f, FALSE, TRUE, FALSE, TRUE);
	rc_vfree(f.ts_i);
	f.ts_i = make_ts_payload(IKEV2_TS_IPV4_ADDR_RANGE, "0.0.0.0",
	    "255.255.255.255");
	(void)ikev2_addr_substitute(&f.child, ts_payl(f.ts_i),
	    ts_payl(f.ts_r));
	TEST_CHECK(f.parent.oa_i == NULL);
	fixture_free(&f);
}

/* IPv6: same originals rule as IPv4. */
static void
test_natoa_originals_v6(void)
{
	struct ts_fixture f;
	struct in6_addr a6;

	fixture_init(&f, TRUE, TRUE, TRUE, TRUE, AF_INET6,
	    IKEV2_TS_IPV6_ADDR_RANGE, TS_I_ADDR6, TS_R_ADDR6);
	TEST_CHECK(ikev2_addr_substitute(&f.child, ts_payl(f.ts_i),
	    ts_payl(f.ts_r)) == 0);
	TEST_CHECK(f.parent.oa_i != NULL &&
	    f.parent.oa_i->sa_family == AF_INET6);
	TEST_CHECK(f.parent.oa_r != NULL &&
	    f.parent.oa_r->sa_family == AF_INET6);
	if (f.parent.oa_i && f.parent.oa_i->sa_family == AF_INET6) {
		test_pton6(TS_I_ADDR6, &a6);
		TEST_CHECK(memcmp(&((struct sockaddr_in6 *)f.parent.oa_i)
		    ->sin6_addr, &a6, sizeof(a6)) == 0);
	}
	if (f.parent.oa_r && f.parent.oa_r->sa_family == AF_INET6) {
		test_pton6(TS_R_ADDR6, &a6);
		TEST_CHECK(memcmp(&((struct sockaddr_in6 *)f.parent.oa_r)
		    ->sin6_addr, &a6, sizeof(a6)) == 0);
	}
	fixture_free(&f);
}

/* ---- N3 response narrowing (RFC 7296 s2.9 + s2.23.1) ---- */

struct tsent {
	uint8_t type, proto;
	uint16_t sport, eport;
	const char *start, *end;
};

/* TS payload (generic header + ts_h + entries) from n entries */
static rc_vchar_t *
make_ts_payload_ents(const struct tsent *e, int n)
{
	rc_vchar_t *v;
	struct ikev2payl_traffic_selector *payl;
	size_t len = sizeof(*payl);
	uint8_t *p;
	int i;

	for (i = 0; i < n; i++)
		len += sizeof(struct ikev2_traffic_selector) + 2 *
		    (e[i].type == IKEV2_TS_IPV6_ADDR_RANGE ? 16 : 4);
	v = rc_vmalloc(len);
	if (v == NULL)
		exit(1);
	memset(v->v, 0, v->l);
	payl = (struct ikev2payl_traffic_selector *)v->v;
	payl->header.payload_length = htons((uint16_t)len);
	payl->tsh.num_ts = (uint8_t)n;
	p = (uint8_t *)(payl + 1);
	for (i = 0; i < n; i++) {
		struct ikev2_traffic_selector *ts = (void *)p;
		size_t al = e[i].type == IKEV2_TS_IPV6_ADDR_RANGE ? 16 : 4;

		ts->ts_type = e[i].type;
		ts->protocol_id = e[i].proto;
		ts->selector_length = htons((uint16_t)(sizeof(*ts) + 2 * al));
		ts->start_port = htons(e[i].sport);
		ts->end_port = htons(e[i].eport);
		ts_pton((uint8_t *)(ts + 1), e[i].type, e[i].start);
		ts_pton((uint8_t *)(ts + 1) + al, e[i].type, e[i].end);
		p += sizeof(*ts) + 2 * al;
	}
	return v;
}

/* selector-derived response form (ts_h + entries, no generic header) */
static rc_vchar_t *
make_selresp(const struct tsent *e, int n)
{
	rc_vchar_t *pl = make_ts_payload_ents(e, n), *v;
	size_t hl = sizeof(struct ikev2_payload_header);

	v = rc_vmalloc(pl->l - hl);
	if (v == NULL)
		exit(1);
	memcpy(v->v, (uint8_t *)pl->v + hl, v->l);
	rc_vfree(pl);
	return v;
}

/* does entry k of a ts_h-form buffer equal e? */
static int
resp_entry_is(const rc_vchar_t *r, int k, const struct tsent *e)
{
	const struct ikev2payl_ts_h *h = (const void *)r->v;
	const uint8_t *p = (const uint8_t *)(h + 1);
	const uint8_t *end = (const uint8_t *)r->v + r->l;
	uint8_t want[32];
	size_t al;
	int i;

	if (k >= h->num_ts)
		return 0;
	for (i = 0; i < k; i++)
		p += ntohs(((const struct ikev2_traffic_selector *)p)
		    ->selector_length);
	{
		const struct ikev2_traffic_selector *ts = (const void *)p;

		al = ts->ts_type == IKEV2_TS_IPV6_ADDR_RANGE ? 16 : 4;
		if (p + sizeof(*ts) + 2 * al > end)
			return 0;
		ts_pton(want, e->type, e->start);
		ts_pton(want + al, e->type, e->end);
		return ts->ts_type == e->type && ts->protocol_id == e->proto &&
		    ntohs(ts->start_port) == e->sport &&
		    ntohs(ts->end_port) == e->eport &&
		    memcmp(ts + 1, want, 2 * al) == 0;
	}
}

#define V4 IKEV2_TS_IPV4_ADDR_RANGE
#define V6 IKEV2_TS_IPV6_ADDR_RANGE

/* A specific proposal (TCP/80) against a wildcard selector must come back
 * as the single post-NAT address WITH the proposed protocol and port -
 * never proto ANY / 0-65535, which would be wider than proposed. */
static void
test_narrow_keeps_proposed_proto_ports(void)
{
	struct tsent prop[] = { { V4, 6, 80, 80, LOCAL4_ADDR, LOCAL4_ADDR } };
	struct tsent sel[] = { { V4, 0, 0, 65535, "0.0.0.0",
	    "255.255.255.255" } };
	struct tsent want = { V4, 6, 80, 80, LOCAL4_ADDR, LOCAL4_ADDR };
	rc_vchar_t *pl = make_ts_payload_ents(prop, 1);
	rc_vchar_t *sr = make_selresp(sel, 1), *r;
	int nm;

	r = ikev2_ts_narrow_to_proposal(ts_payl(pl), sr, &nm);
	TEST_CHECK(r != NULL && nm == 0);
	if (r) {
		TEST_CHECK(((struct ikev2payl_ts_h *)r->v)->num_ts == 1);
		TEST_CHECK(resp_entry_is(r, 0, &want));
		rc_vfree(r);
	}
	rc_vfree(pl);
	rc_vfree(sr);
}

/* A proto-ANY proposal is narrowed to the selector's protocol/port. */
static void
test_narrow_to_selector_proto(void)
{
	struct tsent prop[] = { { V4, 0, 0, 65535, LOCAL4_ADDR, LOCAL4_ADDR } };
	struct tsent sel[] = { { V4, 6, 22, 22, "203.0.113.0",
	    "203.0.113.255" } };
	struct tsent want = { V4, 6, 22, 22, LOCAL4_ADDR, LOCAL4_ADDR };
	rc_vchar_t *pl = make_ts_payload_ents(prop, 1);
	rc_vchar_t *sr = make_selresp(sel, 1), *r;
	int nm;

	r = ikev2_ts_narrow_to_proposal(ts_payl(pl), sr, &nm);
	TEST_CHECK(r != NULL && resp_entry_is(r, 0, &want));
	if (r)
		rc_vfree(r);
	rc_vfree(pl);
	rc_vfree(sr);
}

/* Disjoint protocol or port range: nothing to answer (not a nomem). */
static void
test_narrow_disjoint_rejected(void)
{
	struct tsent prop[] = { { V4, 17, 53, 53, LOCAL4_ADDR, LOCAL4_ADDR } };
	struct tsent sel_proto[] = { { V4, 6, 0, 65535, "0.0.0.0",
	    "255.255.255.255" } };
	struct tsent sel_port[] = { { V4, 0, 1000, 2000, "0.0.0.0",
	    "255.255.255.255" } };
	struct tsent sel_addr[] = { { V4, 0, 0, 65535, "10.0.0.0",
	    "10.255.255.255" } };
	rc_vchar_t *pl = make_ts_payload_ents(prop, 1), *sr;
	int nm;

	sr = make_selresp(sel_proto, 1);
	TEST_CHECK(ikev2_ts_narrow_to_proposal(ts_payl(pl), sr, &nm) == NULL &&
	    nm == 0);
	rc_vfree(sr);
	sr = make_selresp(sel_port, 1);
	TEST_CHECK(ikev2_ts_narrow_to_proposal(ts_payl(pl), sr, &nm) == NULL &&
	    nm == 0);
	rc_vfree(sr);
	sr = make_selresp(sel_addr, 1);
	TEST_CHECK(ikev2_ts_narrow_to_proposal(ts_payl(pl), sr, &nm) == NULL &&
	    nm == 0);
	rc_vfree(sr);
	rc_vfree(pl);
}

/* IPv6 wildcard transport-NAT is narrowed exactly like IPv4, and a
 * mixed-family selector response keeps only same-family intersections. */
static void
test_narrow_ipv6_and_mixed_family(void)
{
	struct tsent prop[] = {
		{ V6, 6, 443, 443, LOCAL6_ADDR, LOCAL6_ADDR },
		{ V6, 0, 0, 65535, LOCAL6_ADDR, LOCAL6_ADDR },
	};
	struct tsent sel[] = {
		{ V4, 0, 0, 65535, "0.0.0.0", "255.255.255.255" },
		{ V6, 0, 0, 65535, "::",
		  "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff" },
	};
	struct tsent w0 = { V6, 6, 443, 443, LOCAL6_ADDR, LOCAL6_ADDR };
	struct tsent w1 = { V6, 0, 0, 65535, LOCAL6_ADDR, LOCAL6_ADDR };
	rc_vchar_t *pl = make_ts_payload_ents(prop, 2);
	rc_vchar_t *sr = make_selresp(sel, 2), *r;
	int nm;

	r = ikev2_ts_narrow_to_proposal(ts_payl(pl), sr, &nm);
	TEST_CHECK(r != NULL);
	if (r) {
		TEST_CHECK(((struct ikev2payl_ts_h *)r->v)->num_ts == 2);
		TEST_CHECK(resp_entry_is(r, 0, &w0));
		TEST_CHECK(resp_entry_is(r, 1, &w1));
		rc_vfree(r);
	}
	rc_vfree(pl);
	rc_vfree(sr);
}

/* Truncated / empty inputs are rejected without reading past them. */
static void
test_narrow_malformed(void)
{
	struct tsent prop[] = { { V4, 0, 0, 65535, LOCAL4_ADDR, LOCAL4_ADDR } };
	struct tsent sel[] = { { V4, 0, 0, 65535, "0.0.0.0",
	    "255.255.255.255" } };
	rc_vchar_t *pl = make_ts_payload_ents(prop, 1);
	rc_vchar_t *sr = make_selresp(sel, 1);
	int nm;

	/* proposal claims 2 TS, carries 1 */
	((struct ikev2payl_traffic_selector *)pl->v)->tsh.num_ts = 2;
	{
		rc_vchar_t *r = ikev2_ts_narrow_to_proposal(ts_payl(pl), sr,
		    &nm);
		TEST_CHECK(r != NULL &&
		    ((struct ikev2payl_ts_h *)r->v)->num_ts == 1);
		if (r)
			rc_vfree(r);
	}
	/* selector response claims 3 TS, carries 1 */
	((struct ikev2payl_traffic_selector *)pl->v)->tsh.num_ts = 1;
	((struct ikev2payl_ts_h *)sr->v)->num_ts = 3;
	{
		rc_vchar_t *r = ikev2_ts_narrow_to_proposal(ts_payl(pl), sr,
		    &nm);
		TEST_CHECK(r != NULL &&
		    ((struct ikev2payl_ts_h *)r->v)->num_ts == 1);
		if (r)
			rc_vfree(r);
	}
	TEST_CHECK(ikev2_ts_narrow_to_proposal(NULL, sr, &nm) == NULL);
	TEST_CHECK(ikev2_ts_narrow_to_proposal(ts_payl(pl), NULL, &nm) == NULL);
	rc_vfree(pl);
	rc_vfree(sr);
}

/* L5: a responder that echoes its wildcard SPD range for a transport
 * NAT-T child must not cost the initiator the child: a returned range
 * that contains the substitute target is narrowed locally to it.  The
 * range has no single original, so that side's OA stays unset. */
static void
test_initiator_range_narrowed(void)
{
	struct ts_fixture f;

	fixture_init_v4(&f, TRUE, TRUE, TRUE, TRUE);
	rc_vfree(f.ts_i);
	rc_vfree(f.ts_r);
	f.ts_i = make_ts_payload(IKEV2_TS_IPV4_ADDR_RANGE, "0.0.0.0",
	    "255.255.255.255");
	f.ts_r = make_ts_payload(IKEV2_TS_IPV4_ADDR_RANGE, "198.51.100.0",
	    "198.51.100.255");
	TEST_CHECK(ikev2_addr_substitute(&f.child, ts_payl(f.ts_i),
	    ts_payl(f.ts_r)) == 0);
	TEST_CHECK(ts_addr_is(f.ts_i, LOCAL4_ADDR, LOCAL4_ADDR));
	TEST_CHECK(ts_addr_is(f.ts_r, REMOTE4_ADDR, REMOTE4_ADDR));
	TEST_CHECK(f.parent.oa_i == NULL);
	TEST_CHECK(f.parent.oa_r == NULL);
	fixture_free(&f);

	/* a range starting AT the target is still narrowed, not kept */
	fixture_init_v4(&f, TRUE, TRUE, TRUE, FALSE);
	rc_vfree(f.ts_i);
	f.ts_i = make_ts_payload(IKEV2_TS_IPV4_ADDR_RANGE, LOCAL4_ADDR,
	    "203.0.113.255");
	TEST_CHECK(ikev2_addr_substitute(&f.child, ts_payl(f.ts_i),
	    ts_payl(f.ts_r)) == 0);
	TEST_CHECK(ts_addr_is(f.ts_i, LOCAL4_ADDR, LOCAL4_ADDR));
	fixture_free(&f);

	/* IPv6 wildcard */
	fixture_init(&f, TRUE, TRUE, TRUE, FALSE, AF_INET6,
	    IKEV2_TS_IPV6_ADDR_RANGE, TS_I_ADDR6, TS_R_ADDR6);
	rc_vfree(f.ts_i);
	f.ts_i = make_ts_payload(IKEV2_TS_IPV6_ADDR_RANGE, "::",
	    "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
	TEST_CHECK(ikev2_addr_substitute(&f.child, ts_payl(f.ts_i),
	    ts_payl(f.ts_r)) == 0);
	TEST_CHECK(ts_addr_is(f.ts_i, LOCAL6_ADDR, LOCAL6_ADDR));
	fixture_free(&f);
}

/* The responder seat still refuses a range proposal (a transport TS MUST
 * carry exactly one address), even one containing the target. */
static void
test_responder_range_still_rejected(void)
{
	struct ts_fixture f;

	fixture_init_v4(&f, FALSE, TRUE, FALSE, TRUE);
	rc_vfree(f.ts_i);
	f.ts_i = make_ts_payload(IKEV2_TS_IPV4_ADDR_RANGE, "0.0.0.0",
	    "255.255.255.255");
	TEST_CHECK(ikev2_addr_substitute(&f.child, ts_payl(f.ts_i),
	    ts_payl(f.ts_r)) == -1);
	TEST_CHECK(ts_addr_is(f.ts_i, "0.0.0.0", "255.255.255.255"));
	fixture_free(&f);
}

/* Handoff case: the response TS is already post-NAT (the responder
 * narrowed to IPN1 as RFC 7296 s2.23.1 says).  The initiator rewrites it
 * to its own local address and keeps IPN1 as the OA. */
static void
test_initiator_response_already_post_nat(void)
{
	struct ts_fixture f;

	fixture_init(&f, TRUE, TRUE, TRUE, FALSE, AF_INET,
	    IKEV2_TS_IPV4_ADDR_RANGE, "192.0.5.254", REMOTE4_ADDR);
	TEST_CHECK(ikev2_addr_substitute(&f.child, ts_payl(f.ts_i),
	    ts_payl(f.ts_r)) == 0);
	TEST_CHECK(ts_addr_is(f.ts_i, LOCAL4_ADDR, LOCAL4_ADDR));
	TEST_CHECK(ts_addr_is(f.ts_r, REMOTE4_ADDR, REMOTE4_ADDR));
	TEST_CHECK(oa_is(f.parent.oa_i, "192.0.5.254"));
	TEST_CHECK(f.parent.oa_r == NULL);
	fixture_free(&f);
}

int
main(int argc, char *argv[])
{
	(void)argc;

	test_init(argv[0]);

	RUN_TEST(test_no_nat_leaves_ts_alone);
	RUN_TEST(test_initiator_transport_substitutes);
	RUN_TEST(test_responder_transport_substitutes);
	RUN_TEST(test_rekey_started_by_ike_responder);
	RUN_TEST(test_tunnel_mode_untouched);
	RUN_TEST(test_initiator_without_selector_untouched);
	RUN_TEST(test_already_matching_ts_untouched);
	RUN_TEST(test_ipv6_transport_substitutes);
	RUN_TEST(test_range_ts_not_substituted);
	RUN_TEST(test_invalid_ts_type_untouched);
	RUN_TEST(test_selector_without_policy_untouched);
	RUN_TEST(test_null_args);
	RUN_TEST(test_all_ts_entries_substituted);
	RUN_TEST(test_family_mismatch_untouched);
	RUN_TEST(test_num_ts_zero_rejected);
	RUN_TEST(test_overrunning_num_ts_rejected);
	RUN_TEST(test_no_parent_rejected);
	RUN_TEST(test_per_side_nat_substitution);
	RUN_TEST(test_natoa_originals);
	RUN_TEST(test_natoa_range_unset);
	RUN_TEST(test_natoa_originals_v6);
	RUN_TEST(test_narrow_keeps_proposed_proto_ports);
	RUN_TEST(test_narrow_to_selector_proto);
	RUN_TEST(test_narrow_disjoint_rejected);
	RUN_TEST(test_narrow_ipv6_and_mixed_family);
	RUN_TEST(test_narrow_malformed);
	RUN_TEST(test_initiator_range_narrowed);
	RUN_TEST(test_responder_range_still_rejected);
	RUN_TEST(test_initiator_response_already_post_nat);

	plog_clean();

	return test_exit_status();
}
