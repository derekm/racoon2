/*
 * rc_str_test - SX-04/Q6 pin for rc_strex() budgets (lib/rc_str.c).
 *
 * Uses the $[ENV] getter only (no config state).  Checks:
 *   - a legitimate 600 KB value that needs two nested passes expands
 *     (the old cumulative per-pass counter charged it ~1.2 MB and failed);
 *   - a final result just under the 1 MiB budget succeeds, just over fails;
 *   - a growth cycle (A = $[A]$[A]) and a non-growing self-reference
 *     (B = $[B]) both fail with -1 and leave *dst untouched;
 *   - undefined name -> -3, unbalanced -> -2, plain text unchanged.
 * Extensionless test -> the sample-wrapper LOG_COMPILER passes an
 * (ignored) sample config.
 */
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "racoon.h"
#include "rc_str.h"

struct rc_log;
char *__wrap_plog(int tag, const char *location, struct rc_log *plg,
    const char *fmt, ...)
{
	(void)tag; (void)location; (void)plg; (void)fmt;
	return NULL;
}
const char *__wrap_plog_location(const char *file, int line, const char *func)
{
	(void)file; (void)line; (void)func;
	return "rc_str_test";
}

static int fails;

static void
chk(const char *name, long got, long want)
{
	printf("%-48s got=%ld want=%ld %s\n", name, got, want,
	    got == want ? "ok" : "FAIL");
	if (got != want)
		fails++;
}

static char *
filler(const char *prefix, size_t n)
{
	size_t pl = strlen(prefix);
	char *s = malloc(pl + n + 1);

	if (!s)
		exit(2);
	memcpy(s, prefix, pl);
	memset(s + pl, 'x', n);
	s[pl + n] = '\0';
	return s;
}

int
main(void)
{
	char *out, *v;
	char sentinel[] = "untouched";
	int rc;

	/* two nested passes, 600 KB final */
	v = filler("$[R2_B]", 600 * 1024);
	setenv("R2_A", v, 1);
	setenv("R2_B", "y", 1);
	out = NULL;
	rc = rc_strex("$[R2_A]", &out);
	chk("nested 600KB value expands", rc, 0);
	chk("nested 600KB final length", out ? (long)strlen(out) : -1,
	    (long)(1 + 600 * 1024));
	chk("nested first byte substituted", out ? out[0] : 0, 'y');
	rc_free(out);
	free(v);

	/* final-size boundary: exactly MAX_OUT ok, MAX_OUT + 1 refused */
	v = filler("", (1 << 20) - 4);
	setenv("R2_C", v, 1);
	out = NULL;
	rc = rc_strex("$[R2_C]abcd", &out);
	chk("final == 1 MiB ok", rc, 0);
	chk("final == 1 MiB length", out ? (long)strlen(out) : -1,
	    (long)(1 << 20));
	rc_free(out);
	out = sentinel;
	rc = rc_strex("$[R2_C]abcde", &out);
	chk("final == 1 MiB + 1 refused", rc, -1);
	chk("refusal leaves *dst", out == sentinel, 1);
	free(v);

	/* growth cycle and non-growing cycle */
	setenv("R2_G", "$[R2_G]$[R2_G]", 1);
	out = sentinel;
	chk("growth cycle refused", rc_strex("$[R2_G]", &out), -1);
	chk("growth cycle leaves *dst", out == sentinel, 1);
	setenv("R2_S", "$[R2_S]", 1);
	out = sentinel;
	chk("self cycle refused", rc_strex("$[R2_S]", &out), -1);
	chk("self cycle leaves *dst", out == sentinel, 1);

	/* classification */
	unsetenv("R2_NOPE");
	out = sentinel;
	chk("undefined -> -3", rc_strex("$[R2_NOPE]", &out), -3);
	chk("unbalanced -> -2", rc_strex("$[R2_A", &out), -2);
	out = NULL;
	chk("plain text", rc_strex("plain text", &out), 0);
	chk("plain text unchanged", out ? strcmp(out, "plain text") : -1, 0);
	rc_free(out);

	printf("RC_STR_TEST_FAILS=%d\n", fails);
	return fails ? 1 : 0;
}
