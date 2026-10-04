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

	unlink(path);
	printf("%s\n", fails ? "FAIL" : "PASS");
	return fails ? 1 : 0;
}
