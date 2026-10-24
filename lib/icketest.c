/*
 * Unit test for the policy directive "initial_child_ke": every accepted
 * value (and the default) must reach struct rcf_policy, the deep copy used
 * by rcf_get_selector() must keep it, and values outside the grammar must
 * be rejected by the parser.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/param.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "racoon.h"

static const char *conf_fmt =
	"selector s_out { direction outbound; src 192.0.2.1; dst 192.0.2.2;"
	" policy_index p; };\n"
	"policy p { action auto_ipsec; ipsec_mode tunnel; %s };\n";

static int
write_conf(const char *path, const char *directive)
{
	FILE *fp = fopen(path, "w");

	if (!fp) {
		perror(path);
		return -1;
	}
	fprintf(fp, conf_fmt, directive);
	return fclose(fp);
}

/* 0 = parsed with the expected value, 1 = mismatch/parse error */
static int
expect(const char *path, const char *directive, rc_type want)
{
	struct rcf_selector *sl = NULL;
	int bad = 0;

	if (write_conf(path, directive))
		return 1;
	if (rcf_read(path, 0)) {
		printf("FAIL: \"%s\" did not parse\n", directive);
		return 1;
	}
	if (rcf_get_selector("s_out", &sl) || !sl || !sl->pl) {
		printf("FAIL: \"%s\": no selector/policy\n", directive);
		bad = 1;
	} else if (sl->pl->initial_child_ke != want) {
		printf("FAIL: \"%s\": initial_child_ke=%d (%s), want %d (%s)\n",
		    directive, sl->pl->initial_child_ke,
		    rct2str(sl->pl->initial_child_ke), want, rct2str(want));
		bad = 1;
	} else
		printf("ok: \"%s\" -> %s\n", directive, rct2str(want));
	if (sl)
		rcf_free_selector(sl);
	rcf_clean();
	return bad;
}

static int
reject(const char *path, const char *directive)
{
	if (write_conf(path, directive))
		return 1;
	if (rcf_read(path, 0) == 0) {
		printf("FAIL: \"%s\" was accepted\n", directive);
		rcf_clean();
		return 1;
	}
	printf("ok: \"%s\" rejected\n", directive);
	return 0;
}

/* mark/if_id decode on the policy; rcf_get_selector() deep-copies it, so
 * this also proves the deep copy preserves the fields. */
static int
expect_mark(const char *path, const char *directive,
	    unsigned long want_v, unsigned long want_m, unsigned long want_if)
{
	struct rcf_selector *sl = NULL;
	int bad = 0;

	if (write_conf(path, directive))
		return 1;
	if (rcf_read(path, 0)) {
		printf("FAIL: \"%s\" did not parse\n", directive);
		return 1;
	}
	if (rcf_get_selector("s_out", &sl) || !sl || !sl->pl) {
		printf("FAIL: \"%s\": no selector/policy\n", directive);
		bad = 1;
	} else {
		if (sl->pl->mark != want_v) {
			printf("FAIL: \"%s\": mark=%#lx want %#lx\n",
			    directive, (unsigned long)sl->pl->mark, want_v);
			bad = 1;
		}
		if (sl->pl->mark_mask != want_m) {
			printf("FAIL: \"%s\": mark_mask=%#lx want %#lx\n",
			    directive, (unsigned long)sl->pl->mark_mask, want_m);
			bad = 1;
		}
		if (sl->pl->if_id != want_if) {
			printf("FAIL: \"%s\": if_id=%lu want %lu\n",
			    directive, (unsigned long)sl->pl->if_id, want_if);
			bad = 1;
		}
		if (!bad)
			printf("ok: \"%s\" -> mark=%#lx mask=%#lx if_id=%lu\n",
			    directive, want_v, want_m, want_if);
	}
	if (sl)
		rcf_free_selector(sl);
	rcf_clean();
	return bad;
}

/* offload lives on the SA (full selector/policy/ipsec/sa chain). */
static int
offload_case(const char *path, const char *dir, const char *want_dev,
	     int want_reject)
{
	struct rcf_selector *sl = NULL;
	struct rcf_ipsec *ip;
	const struct rcf_sa *sa = NULL;
	int bad = 0;
	FILE *fp;

	if ((fp = fopen(path, "w")) == NULL)
		return 1;
	fprintf(fp,
	    "selector s_off { direction outbound; src 192.0.2.1;"
	    " dst 192.0.2.2; policy_index p_off; };\n"
	    "policy p_off { action auto_ipsec; ipsec_mode tunnel;"
	    " ipsec_index { ipsec_off; }; };\n"
	    "ipsec ipsec_off { ipsec_sa_lifetime_time 3600 sec;"
	    " sa_index esp_off; };\n"
	    "sa esp_off { sa_protocol esp; esp_enc_alg { aes_gcm; };"
	    " esp_auth_alg { non_auth; }; offload { dev \"%s\"; dir %s; }; };\n",
	    want_dev, dir);
	fclose(fp);
	if (rcf_read(path, 0)) {
		if (want_reject) {
			printf("ok: offload dir=%s rejected\n", dir);
			return 0;
		}
		printf("FAIL: offload dir=%s did not parse\n", dir);
		return 1;
	}
	if (want_reject) {
		printf("FAIL: offload dir=%s was accepted\n", dir);
		rcf_clean();
		return 1;
	}
	if (rcf_get_selector("s_off", &sl) || !sl || !sl->pl) {
		printf("FAIL: offload dir=%s: no selector/policy\n", dir);
		bad = 1;
	} else {
		for (ip = sl->pl->ips; ip; ip = ip->next)
			if (ip->sa_esp) {
				sa = ip->sa_esp;
				break;
			}
		if (!sa) {
			printf("FAIL: offload dir=%s: no esp sa resolved\n", dir);
			bad = 1;
		} else {
			if (strcmp(sa->offload_ifname, want_dev) != 0) {
				printf("FAIL: offload dir=%s: dev='%s' want '%s'\n",
				    dir, sa->offload_ifname, want_dev);
				bad = 1;
			}
			{
				rc_type want_fl = (strcmp(dir, "in") == 0) ? 2 : 0;
				if (sa->offload_flags != want_fl) {
					printf("FAIL: offload dir=%s: flags=%u want %u\n",
					    dir, sa->offload_flags, want_fl);
					bad = 1;
				}
			}
			if (!bad)
				printf("ok: offload dir=%s -> dev='%s' flags=%u\n",
				    dir, want_dev, strcmp(dir, "in") == 0 ? 2 : 0);
		}
	}
	if (sl)
		rcf_free_selector(sl);
	rcf_clean();
	return bad;
}

/* offload block without a dev must be rejected fail-closed (silent no-op). */
static int
reject_offload_nodev(const char *path)
{
	FILE *fp;

	if ((fp = fopen(path, "w")) == NULL)
		return 1;
	fprintf(fp,
	    "selector s_off { direction outbound; src 192.0.2.1;"
	    " dst 192.0.2.2; policy_index p_off; };\n"
	    "policy p_off { action auto_ipsec; ipsec_mode tunnel;"
	    " ipsec_index { ipsec_off; }; };\n"
	    "ipsec ipsec_off { ipsec_sa_lifetime_time 3600 sec;"
	    " sa_index esp_off; };\n"
	    "sa esp_off { sa_protocol esp; esp_enc_alg { aes_gcm; };"
	    " esp_auth_alg { non_auth; }; offload { dir in; }; };\n");
	fclose(fp);
	if (rcf_read(path, 0) == 0) {
		printf("FAIL: offload without dev was accepted\n");
		rcf_clean();
		return 1;
	}
	printf("ok: offload without dev rejected\n");
	return 0;
}

int
main(void)
{
	char path[] = "/tmp/icketest.XXXXXX";
	int fd, fails = 0;

	if ((fd = mkstemp(path)) < 0) {
		perror("mkstemp");
		return 1;
	}
	close(fd);
	if (rbuf_init(8, 80, 4, 160, 4))
		return 1;
	plog_setmode(RCT_LOGMODE_NORMAL, NULL, "icketest", 1, 0);

	fails += expect(path, "", RCT_ICKE_OFF);
	fails += expect(path, "initial_child_ke off;", RCT_ICKE_OFF);
	fails += expect(path, "initial_child_ke immediate;", RCT_ICKE_IMMEDIATE);
	fails += expect(path, "initial_child_ke childless;", RCT_ICKE_CHILDLESS);
	fails += reject(path, "initial_child_ke on;");
	fails += reject(path, "initial_child_ke;");
	fails += reject(path, "initial_child_ke sometimes;");

	/* mark / if_id flow selector (policy) — brace-block directives carry a
	 * trailing ';' (list EOS), like offload/oar ipsec blocks */
	fails += expect_mark(path,
	    "mark { value 0x100; mask 0xff; };", 0x100, 0xff, 0);
	fails += expect_mark(path, "if_id 0xffffffff;", 0, 0, 0xffffffffUL);
	fails += expect_mark(path,
	    "mark { value 0x100; }; if_id 7;", 0x100, 0xffffffffUL, 7);
	/* offload (SA) — full chain; dir out/in decode + bad dir reject */
	fails += offload_case(path, "out", "eth0", 0);
	fails += offload_case(path, "in", "eth0", 0);
	fails += offload_case(path, "sideways", "", 1);
	fails += reject_offload_nodev(path);
	/* fail-closed grammar rejects */
	fails += reject(path, "mark { bogus 1; }");
	fails += reject(path, "mark { value 0x100;");

	unlink(path);
	printf("%s\n", fails ? "FAIL" : "PASS");
	return fails ? 1 : 0;
}
