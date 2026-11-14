/*
 * childfailtest.c -- G02 responder CHILD_SA install failure (RFC 7296
 * s1.3, s2.1, s3.10.1).
 *
 * A responder whose ikev2_add_ipsec_sa() fails for a CREATE_CHILD_SA
 * request must answer that request with N(NO_PROPOSAL_CHOSEN) (built on
 * the request's Message ID, flagged as a response) and abort the new
 * child; it must NOT stay silent (the initiator then retransmits until
 * its IKE SA dies, killing the old child too), and it must NOT run the
 * "child up" side effects (SCRIPT_PHASE2_UP hook, resume record save)
 * for the child it just aborted.
 *
 * Drives the REAL dispatcher: ikev2_child_state_set(child, MATURE) on a
 * responder child runs the real ikev2_create_child_responder_cont, the
 * real ikev2_add_ipsec_sa (failed through a --wrap of
 * ikev2_proposal_to_ipsec), the real ikev2_child_responder_install_failed
 * / ikev2_createchild_responder_send_error and the real ikev2_child_abort.
 * Only the crypto/packet boundary (ikev2_packet_construct,
 * ikev2_transmit_response) and the side-effect sinks (script hook,
 * resume save) are wrapped so they can be observed.
 */
#include "config.h"
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>

#include "racoon.h"
#include "plog.h"
#include "isakmp.h"
#include "isakmp_impl.h"
#include "ikev2.h"
#include "ikev2_impl.h"
#include "ike_conf.h"
#include "ike_pfkey.h"
#include "script.h"

#include "test_util.h"

TEST_MAIN_STUBS()

static int fails;

#define CK(cond, what) do {						\
	if (!(cond)) {							\
		++fails;						\
		printf("FAIL: %s (line %d)\n", (what), __LINE__);	\
	} else								\
		printf("ok: %s\n", (what));				\
} while (0)

/* --- observation state --- */
static int n_prop2ipsec, n_construct, n_transmit, n_acq_err;
static int n_up_hook, n_resume_save;
static int construct_fail, transmit_fail;
static int last_exch, last_flags;
static uint32_t last_msgid;
static int last_npayl, last_ptype, last_notify;
static int last_state_at_construct;
static struct ikev2_child_sa *watched;

int
__wrap_ikev2_proposal_to_ipsec(struct ikev2_child_sa *c,
    struct ikev2_child_param *p, struct prop_pair *pp,
    int (*fn)(struct ikev2_child_sa *, struct rcpfk_msg *, void *), void *a)
{
	(void)c; (void)p; (void)pp; (void)fn; (void)a;
	++n_prop2ipsec;
	return -1;		/* the synchronous install failure */
}

rc_vchar_t *
__wrap_ikev2_packet_construct(int exch, int flags, uint32_t msgid,
    struct ikev2_sa *sa, struct ikev2_payloads *payl)
{
	(void)sa;
	++n_construct;
	last_exch = exch;
	last_flags = flags;
	last_msgid = msgid;
	last_npayl = payl->num;
	last_ptype = payl->num > 0 ? (int)payl->payloads[0].type : -1;
	last_notify = -1;
	if (payl->num > 0 && payl->payloads[0].data &&
	    payl->payloads[0].data->l >= sizeof(struct ikev2payl_notify_h)) {
		struct ikev2payl_notify_h *nh =
		    (struct ikev2payl_notify_h *)payl->payloads[0].data->v;
		last_notify = get_uint16(&nh->notify_message_type);
	}
	last_state_at_construct = watched ? (int)watched->state : -1;
	if (construct_fail)
		return NULL;
	return rc_vmalloc(28);
}

int
__wrap_ikev2_transmit_response(struct ikev2_sa *sa, rc_vchar_t *pkt,
    struct sockaddr *l, struct sockaddr *r)
{
	(void)sa; (void)l; (void)r;
	++n_transmit;
	if (transmit_fail)
		return -1;	/* caller keeps ownership (LSan checks it) */
	rc_vfree(pkt);		/* the real one stores it in response_info */
	return 0;
}

void
__wrap_ikev2_child_script_hook(struct ikev2_child_sa *c, int script)
{
	(void)c;
	if (script == SCRIPT_PHASE2_UP || script == SCRIPT_PHASE2_REKEY)
		++n_up_hook;
}

int
__wrap_ikev2_resume_save(struct ikev2_sa *sa)
{
	(void)sa;
	++n_resume_save;
	return 0;
}

static int
stub_acquire_error(struct rcpfk_msg *m)
{
	(void)m;
	++n_acq_err;
	return 0;
}

static struct sadb_request_method stub_method = {
	.acquire_error = stub_acquire_error,
};

static void
reset(void)
{
	n_prop2ipsec = n_construct = n_transmit = n_acq_err = 0;
	n_up_hook = n_resume_save = 0;
	construct_fail = transmit_fail = 0;
	last_exch = last_flags = last_npayl = last_ptype = last_notify = -1;
	last_msgid = 0;
	last_state_at_construct = -1;
}

static void
run_case(const char *name, int ike_state, int is_ike_initiator,
	 int cfail, int tfail)
{
	struct ikev2_sa *sa = calloc(1, sizeof(*sa));
	struct ikev2_child_sa *c = calloc(1, sizeof(*c));
	struct sockaddr_storage ls, rs;
	struct prop_pair *my_props[2] = { NULL, NULL };
	char what[256];

	if (!sa || !c) {
		++fails;
		free(sa); free(c);
		return;
	}
	test_make_addr(&ls, AF_INET, "192.0.2.1", 500);
	test_make_addr(&rs, AF_INET, "192.0.2.2", 500);
	sa->local = (struct sockaddr *)&ls;
	sa->remote = (struct sockaddr *)&rs;
	sa->state = ike_state;
	sa->is_initiator = is_ike_initiator;
	IKEV2_CHILD_LIST_INIT(&sa->children);
	c->parent = sa;
	c->is_initiator = FALSE;
	c->message_id = 0x2a;
	c->state = IKEV2_CHILD_STATE_GETSPI_DONE;
	c->sadb_request.method = &stub_method;
	c->my_proposal = my_props;	/* [1] = the matched proposal slot */
	LIST_INIT(&c->lease_list);
	watched = c;

	reset();
	construct_fail = cfail;
	transmit_fail = tfail;
	printf("--- %s ---\n", name);
	ikev2_child_state_set(c, IKEV2_CHILD_STATE_MATURE);

	snprintf(what, sizeof(what), "%s: the real install ran and failed",
		 name);
	CK(n_prop2ipsec == 1, what);
	snprintf(what, sizeof(what), "%s: child aborted (EXPIRED, "
		 "acquire_error sent)", name);
	CK(c->state == IKEV2_CHILD_STATE_EXPIRED && n_acq_err == 1, what);
	snprintf(what, sizeof(what), "%s: no child-up side effects "
		 "(up hook %d, resume save %d)", name, n_up_hook,
		 n_resume_save);
	CK(n_up_hook == 0 && n_resume_save == 0, what);

	if (ike_state == IKEV2_STATE_ESTABLISHED) {
		snprintf(what, sizeof(what), "%s: exactly one response built",
			 name);
		CK(n_construct == 1, what);
		snprintf(what, sizeof(what), "%s: CREATE_CHILD_SA response on "
			 "the request msgid (exch %d flags 0x%x id 0x%x)",
			 name, last_exch, last_flags, (unsigned)last_msgid);
		CK(last_exch == IKEV2EXCH_CREATE_CHILD_SA &&
		   (last_flags & IKEV2FLAG_RESPONSE) &&
		   !!(last_flags & IKEV2FLAG_INITIATOR) == !!is_ike_initiator &&
		   last_msgid == 0x2a, what);
		snprintf(what, sizeof(what), "%s: sole payload is "
			 "N(NO_PROPOSAL_CHOSEN) (npayl %d type %d notify %d)",
			 name, last_npayl, last_ptype, last_notify);
		CK(last_npayl == 1 && last_ptype == IKEV2_PAYLOAD_NOTIFY &&
		   last_notify == IKEV2_NO_PROPOSAL_CHOSEN, what);
		snprintf(what, sizeof(what), "%s: error answered before the "
			 "abort (state at build %d)", name,
			 last_state_at_construct);
		CK(last_state_at_construct == IKEV2_CHILD_STATE_MATURE, what);
		snprintf(what, sizeof(what), "%s: transmit %s", name,
			 cfail ? "skipped (no packet)" : "attempted");
		CK(n_transmit == (cfail ? 0 : 1), what);
	} else {
		snprintf(what, sizeof(what), "%s: no child-only response in "
			 "IKE_AUTH (construct %d transmit %d)", name,
			 n_construct, n_transmit);
		CK(n_construct == 0 && n_transmit == 0, what);
	}

	watched = NULL;
	free(c);
	free(sa);
}

int
main(int argc, char **argv)
{
	(void)argc;
	test_init(argv[0]);

	run_case("rekey responder, IKE responder", IKEV2_STATE_ESTABLISHED,
		 FALSE, 0, 0);
	run_case("rekey responder, IKE initiator", IKEV2_STATE_ESTABLISHED,
		 TRUE, 0, 0);
	run_case("transmit failure (no leak)", IKEV2_STATE_ESTABLISHED,
		 FALSE, 0, 1);
	run_case("construct failure", IKEV2_STATE_ESTABLISHED, FALSE, 1, 0);
	run_case("IKE_AUTH initial child", IKEV2_STATE_RES_IKE_AUTH_RCVD,
		 FALSE, 0, 0);

	printf("%s\n", fails ? "childfailtest: FAILED" : "childfailtest: OK");
	return fails ? 1 : 0;
}
