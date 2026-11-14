/*
 * spmdoomtest.c -- RB-03 / S6: spmd fails CLOSED when the rc_vmem2str
 * scratch allocation fails (OOM), instead of silently dropping SPD work.
 *
 *   A. spmd_pfkey_init with an FQDN selector: any of the three scratch
 *      conversions failing makes init return -1 and registers no PF_KEY
 *      receiver (was: the selector was skipped, init returned 0 with the
 *      policy missing from the SPD).
 *   B. spmd_spd_update: a failed selector conversion sends NO SPDUPDATE
 *      (was: the policy was installed without a spid<->slid binding, so it
 *      could never be deleted by selector).
 *   C. spmd_spd_delete_by_slid: a failed conversion while matching
 *      selectors reports failure and queues no delete (was: the selector
 *      was skipped, "not found", and the call still returned 0).
 *   Controls prove each fail-closed check is reachable: the same calls
 *   succeed (and do their work) with the scratch working.
 *
 * Links the spmd objects (all but main.c) with --wrap seams for the
 * scratch converter, the config accessors and the PF_KEY / task sinks.
 */
#include "spmd_includes.h"

extern int spmd_spd_update(struct rcf_selector *, struct rcpfk_msg *, int);

/* --- main.c globals the spmd objects reference --- */
char spmd_version[] = "test";
int spmd_foreground = 1;
int spmd_nss;
void
spmd_exit(int status)
{
	exit(status);
}

static int fails;
#define CK(c, what) do {						\
	if (!(c)) { ++fails; printf("FAIL: %s (line %d)\n", (what), __LINE__); } \
	else printf("ok: %s\n", (what));				\
} while (0)

/* --- seams --- */
static int vm_calls, vm_fail_at, vm_fail_all;
const char *__real_rc_vmem2str(const rc_vchar_t *);
const char *
__wrap_rc_vmem2str(const rc_vchar_t *v)
{
	++vm_calls;
	if (vm_fail_all || (vm_fail_at && vm_calls == vm_fail_at))
		return NULL;
	return __real_rc_vmem2str(v);
}

static struct rcf_selector *g_sl;
int
__wrap_rcf_get_selectorlist(struct rcf_selector **slp)
{
	*slp = g_sl;
	return 0;
}
void
__wrap_rcf_free_selector(struct rcf_selector *sl)
{
	(void)sl;	/* the test owns the synthetic list */
}
int
__wrap_rcf_spmd_resolver(void)
{
	return RCT_BOOL_ON;
}
int
__wrap_rcf_get_remotebyindex(rc_vchar_t *idx, struct rcf_remote **rm)
{
	(void)idx;
	*rm = NULL;
	return -1;
}

static struct rcpfk_cb *g_cb;
int
__wrap_rcpfk_init(struct rcpfk_msg *rc, struct rcpfk_cb *cb)
{
	g_cb = cb;
	rc->so = -1;
	return 0;
}
int
__wrap_rcpfk_send_spddump(struct rcpfk_msg *rc)
{
	(void)rc;
	return 0;
}
static int n_spdupdate;
int
__wrap_rcpfk_send_spdupdate(struct rcpfk_msg *rc)
{
	(void)rc;
	++n_spdupdate;
	return 0;
}
int
__wrap_rcpfk_handler(struct rcpfk_msg *rc)
{
	(void)rc;
	return 0;
}

static int n_read_tasks, n_write_tasks;
void
__wrap_task_list_add(struct task *t, struct task_list *tl)
{
	if (tl == &spmd_task_root->read)
		++n_read_tasks;
	else if (tl == &spmd_task_root->write) {
		++n_write_tasks;
		if (t->msg)
			spmd_free_rcpfk_msg((struct rcpfk_msg *)t->msg);
	}
	t->msg = NULL;
	task_free(t);
}

/* --- synthetic config --- */
static rc_vchar_t *
vs(const char *s)
{
	return rc_str2vmem(s);
}

static struct rcf_selector *
mk_fqdn_sel(void)
{
	struct rcf_selector *sl = calloc(1, sizeof(*sl));
	struct rc_addrlist *s = calloc(1, sizeof(*s)), *d = calloc(1, sizeof(*d));
	struct rcf_policy *pl = calloc(1, sizeof(*pl));

	sl->sl_index = vs("fqdnsel");
	sl->direction = RCT_DIR_OUTBOUND;
	s->type = RCT_ADDR_FQDN;
	s->a.vstr = vs("a.example.test");
	d->type = RCT_ADDR_FQDN;
	d->a.vstr = vs("b.example.test");
	sl->src = s;
	sl->dst = d;
	pl->action = RCT_ACT_NONE;
	sl->pl = pl;
	return sl;
}

static struct rcf_selector *
mk_inet_sel(const char *idx)
{
	struct rcf_selector *sl = calloc(1, sizeof(*sl));
	struct rcf_policy *pl = calloc(1, sizeof(*pl));

	sl->sl_index = vs(idx);
	sl->direction = RCT_DIR_OUTBOUND;
	pl->action = RCT_ACT_NONE;
	pl->ipsec_mode = RCT_IPSM_TRANSPORT;
	sl->pl = pl;
	return sl;
}

static void
free_sel(struct rcf_selector *sl)
{
	struct rc_addrlist *al[2];
	int i;

	al[0] = sl->src;
	al[1] = sl->dst;
	for (i = 0; i < 2; i++) {
		if (al[i] && al[i]->type == RCT_ADDR_FQDN)
			rc_vfree(al[i]->a.vstr);
		free(al[i]);
	}
	rc_vfree(sl->sl_index);
	free(sl->pl);
	free(sl);
}

static struct rcpfk_msg *
mk_rc(void)
{
	struct rcpfk_msg *rc = spmd_alloc_rcpfk_msg();
	struct sockaddr_in a;

	memset(&a, 0, sizeof(a));
	a.sin_family = AF_INET;
#ifdef HAVE_SA_LEN
	a.sin_len = sizeof(a);
#endif
	inet_pton(AF_INET, "192.0.2.1", &a.sin_addr);
	rc->sp_src = rcs_sadup((struct sockaddr *)&a);
	inet_pton(AF_INET, "192.0.2.2", &a.sin_addr);
	rc->sp_dst = rcs_sadup((struct sockaddr *)&a);
	rc->pref_src = rc->pref_dst = 32;
	rc->dir = RCT_DIR_OUTBOUND;
	rc->samode = RCT_IPSM_TRANSPORT;
	rc->pltype = RCT_ACT_NONE;
	return rc;
}

static void
reset(void)
{
	vm_calls = vm_fail_at = vm_fail_all = 0;
	n_spdupdate = n_read_tasks = n_write_tasks = 0;
}

int
main(void)
{
	struct rcf_selector *fsel, *isel;
	struct rcpfk_msg *rc, ev;
	int k, r;
	char what[160];

	plog_setmode(RCT_LOGMODE_DEBUG, NULL, "spmdoomtest", 1, 1);
	if (rbuf_init(8, 80, 4, 160, 4) != 0) {
		printf("FAIL: rbuf_init\n");
		return 1;
	}
	task_init();

	/* A: init fails closed on each of the 3 scratch conversions */
	fsel = mk_fqdn_sel();
	g_sl = fsel;
	for (k = 1; k <= 3; k++) {
		reset();
		vm_fail_at = k;
		r = spmd_pfkey_init();
		snprintf(what, sizeof(what), "A: scratch OOM at conversion %d "
		    "-> init fails, no receiver (r=%d tasks=%d)", k, r,
		    n_read_tasks);
		CK(r == -1 && n_read_tasks == 0, what);
	}
	reset();
	r = spmd_pfkey_init();
	CK(r == 0 && n_read_tasks == 1 && vm_calls >= 3,
	   "A control: init succeeds and registers the PF_KEY receiver");

	/* B: SP update with the binding conversion failing sends nothing */
	isel = mk_inet_sel("inetsel");
	g_sl = isel;
	reset();
	vm_fail_all = 1;
	rc = mk_rc();
	r = spmd_spd_update(isel, rc, 1);
	snprintf(what, sizeof(what), "B: scratch OOM -> update refused, no "
	    "SPDUPDATE sent (r=%d sent=%d)", r, n_spdupdate);
	CK(r == -1 && n_spdupdate == 0, what);
	spmd_free_rcpfk_msg(rc);

	reset();
	rc = mk_rc();
	r = spmd_spd_update(isel, rc, 1);
	CK(r == 0 && n_spdupdate == 1, "B control: update sent");
	/* the kernel's SPDUPDATE reply binds the seq to spid 777 */
	memset(&ev, 0, sizeof(ev));
	ev.seq = rc->seq;
	ev.slid = 777;
	CK(g_cb && g_cb->cb_spdupdate, "PF_KEY callbacks registered");
	if (g_cb && g_cb->cb_spdupdate)
		g_cb->cb_spdupdate(&ev);
	spmd_free_rcpfk_msg(rc);

	/* C: delete by slid with the selector match failing */
	reset();
	vm_fail_all = 1;
	r = spmd_spd_delete_by_slid("inetsel");
	snprintf(what, sizeof(what), "C: scratch OOM -> delete reports "
	    "failure, nothing queued (r=%d queued=%d)", r, n_write_tasks);
	CK(r == -1 && n_write_tasks == 0, what);

	reset();
	r = spmd_spd_delete_by_slid("inetsel");
	CK(r == 0 && n_write_tasks == 1,
	   "C control: delete by slid queues the SPDDELETE");

	g_sl = NULL;
	free_sel(fsel);
	free_sel(isel);
	printf("spmdoomtest: %s\n", fails ? "FAILED" : "OK");
	return fails ? 1 : 0;
}
