/*
 * sd_listenfds_test - SA-01/N4 pin for lib/sd_listenfds.c.
 *
 * rc_parse_act_meta(): strict decimal only; *valp untouched on every
 * rejection.  rc_listenfds(): end to end via LISTEN_PID/LISTEN_FDS in a
 * forked child per case (the result is cached per process).  No real
 * descriptors are inherited; fds 3.. only get FD_CLOEXEC set.
 * Extensionless test -> the sample-wrapper LOG_COMPILER passes an
 * (ignored) sample config.
 */
#include "config.h"
#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "sd_listenfds.h"

static int fails;

static void
chk(const char *name, int got, int want)
{
	printf("%-44s got=%d want=%d %s\n", name, got, want,
	    got == want ? "ok" : "FAIL");
	if (got != want)
		fails++;
}

static void
parse(const char *in, int want_rc, int want_val)
{
	int v = -12345;
	int rc = rc_parse_act_meta(in, &v);
	char name[96];

	snprintf(name, sizeof(name), "parse \"%s\" rc", in ? in : "(null)");
	chk(name, rc, want_rc);
	snprintf(name, sizeof(name), "parse \"%s\" val", in ? in : "(null)");
	chk(name, v, want_rc ? want_val : -12345);
}

/* run rc_listenfds() in a child with the given env; return its result */
static int
listenfds_with(const char *pid, const char *fds)
{
	pid_t c;
	int st;

	c = fork();
	if (c < 0)
		exit(2);
	if (c == 0) {
		char buf[32];

		if (pid && strcmp(pid, "SELF") == 0) {
			snprintf(buf, sizeof(buf), "%ld", (long)getpid());
			pid = buf;
		}
		if (pid)
			setenv("LISTEN_PID", pid, 1);
		else
			unsetenv("LISTEN_PID");
		if (fds)
			setenv("LISTEN_FDS", fds, 1);
		else
			unsetenv("LISTEN_FDS");
		_exit(rc_listenfds());
	}
	if (waitpid(c, &st, 0) != c || !WIFEXITED(st))
		return -1;
	return WEXITSTATUS(st);
}

int
main(void)
{
	parse("0", 1, 0);
	parse("3", 1, 3);
	parse("2147483647", 1, 2147483647);
	parse("2147483648", 0, 0);
	parse("99999999999999999999", 0, 0);
	parse("-1", 0, 0);
	parse("+3", 0, 0);
	parse(" 3", 0, 0);
	parse("3 ", 0, 0);
	parse("3junk", 0, 0);
	parse("0x10", 0, 0);
	parse("", 0, 0);
	parse(NULL, 0, 0);
	chk("parse NULL valp", rc_parse_act_meta("3", NULL), 0);

	chk("listenfds pid=self fds=2", listenfds_with("SELF", "2"), 2);
	chk("listenfds pid=self fds=40 (clamp 16)",
	    listenfds_with("SELF", "40"), 16);
	chk("listenfds pid=self fds=\"+2\"", listenfds_with("SELF", "+2"), 0);
	chk("listenfds pid=self fds=\" 2\"", listenfds_with("SELF", " 2"), 0);
	chk("listenfds pid=self fds=0", listenfds_with("SELF", "0"), 0);
	chk("listenfds pid=1 fds=2", listenfds_with("1", "2"), 0);
	chk("listenfds no env", listenfds_with(NULL, NULL), 0);

	printf("SD_LISTENFDS_TEST_FAILS=%d\n", fails);
	return fails ? 1 : 0;
}
