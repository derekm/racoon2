/*
 * pidfile_test - unit (known-answer) regression harness for the lib/pidfile.c
 * hardening set (PF-01 reader, PF-02 writer, PF-04 oversize path, PF-05
 * CLOEXEC).  Mirrors lib/vmbuf_test.c: it links the real pidfile.lo and
 * interposes write()/open() via -Wl,--wrap so the production code under test
 * is exercised with the SAME source used in the suite.
 *
 * It is RED-capable: under the UNFIXED pidfile.c the reader wrongly accepts
 * negative/zero/overflow/trailing-junk input and the writer accepts a partial
 * or empty write as full success; under the fixed code every probe passes.
 *
 * Policy under test (the reader's chosen whitespace/newline policy):
 *   the whole file must be exactly one positive decimal integer in
 *   [1, INT_MAX] (pid_t == int) optionally surrounded by ASCII whitespace
 *   (spaces/tabs/newlines - a single trailing newline and leading/trailing
 *   whitespace are accepted).  Everything else is rejected: empty, nonnumeric,
 *   zero, negative, signs, trailing junk ("123junk"), overflow past INT_MAX,
 *   and overlong input.  A range-checked parse is used (never %d clamping).
 *
 * PF-02 policy: rc_make_pidfile must fully publish the pidstring - loop over
 * write(), retrying on EINTR and continuing on partial writes; a terminal
 * error (EIO, or a persistent 0-length write) is a failure that follows the
 * documented cleanup (file unlinked via the dev/ino safeguard, state reset).
 *
 * PF-04: an oversized progname must be rejected in rc_make_pidfile_on_dir
 * BEFORE any open(), so no truncated-named pidfile is created.
 *
 * PF-05: the writer fd must be close-on-exec, so a fork+exec'd helper cannot
 * prolong the flock on an abrupt death of the daemon.
 */

#include "config.h"

#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "plog.h"
#include "pidfile.h"

static int nchecks = 0;
static int nfails = 0;

#define CHECK(cond)							\
	do {								\
		nchecks++;						\
		if (!(cond)) {						\
			printf("FAIL %s:%d: %s\n", __FILE__, __LINE__,	\
			    #cond);					\
			nfails++;					\
		}							\
	} while (0)

/* ---------- plog stubs: pidfile.lo references plog/plog_location,
 * which normally live in the full lib; provide them here. ---------- */
char *
plog(int tag, const char *location, struct rc_log *plg, const char *fmt, ...)
{
	(void)tag; (void)location; (void)plg; (void)fmt;
	return NULL;
}

const char *
plog_location(const char *file, int line, const char *func)
{
	static char loc[256];
	snprintf(loc, sizeof(loc), "%s:%d:%s", file, line,
	    func ? func : "");
	return loc;
}

/* ---------- fault-injection wrappers (linked with
 * -Wl,--wrap=write --wrap=open) ----------
 * __wrap_open records the fd of the writer's open(O_WRONLY|O_CREAT) of the
 * monitored pidfile path, so __wrap_write can simulate short/zero/EINTR/EIO
 * results for exactly that fd; every other descriptor passes through. */

enum sim_mode { SIM_NONE, SIM_SHORT, SIM_ZERO, SIM_EINTR, SIM_EIO };

static enum sim_mode g_sim = SIM_NONE;
static int g_eintr_left = 0;
static const char *g_monitor_path = NULL;
static int s_pidfile_fd = -1;

int __real_open(const char *file, int flags, ...);
int __wrap_open(const char *file, int flags, ...)
{
	mode_t mode = 0;

	if (flags & O_CREAT) {
		va_list ap;
		va_start(ap, flags);
		mode = (mode_t)va_arg(ap, int);
		va_end(ap);
	}
	{
		int fd = __real_open(file, flags, mode);

		if (fd >= 0 &&
		    (flags & O_ACCMODE) == O_WRONLY &&
		    g_monitor_path != NULL &&
		    strcmp(g_monitor_path, file) == 0)
			s_pidfile_fd = fd;
		return fd;
	}
}

ssize_t __real_write(int fd, const void *buf, size_t count);
ssize_t __wrap_write(int fd, const void *buf, size_t count)
{
	if (fd == s_pidfile_fd) {
		switch (g_sim) {
		case SIM_SHORT:
			/* once: a genuine partial write - really write count-1
			 * bytes and return count-1 (short), so the writer must
			 * loop to publish the last byte. */
			g_sim = SIM_NONE;
			if (count > 1) {
				ssize_t r = __real_write(fd, buf, count - 1);

				if (r < 0)
					return r;
				return (ssize_t)(count - 1);
			}
			return __real_write(fd, buf, count);
		case SIM_ZERO:
			return 0;	/* persistent 0-length write */
		case SIM_EINTR:
			if (g_eintr_left > 0) {
				g_eintr_left--;
				errno = EINTR;
				return -1;
			}
			break;
		case SIM_EIO:
			errno = EIO;
			return -1;
		case SIM_NONE:
		default:
			break;
		}
	}
	return __real_write(fd, buf, count);
}

/* ---------- helpers ---------- */

static int
file_contents(const char *path, char *out, size_t outsz)
{
	FILE *f = fopen(path, "rb");
	size_t n;

	if (f == NULL)
		return -1;
	n = fread(out, 1, outsz - 1, f);
	fclose(f);
	out[n] = '\0';
	return 0;
}

static int
write_file(const char *path, const char *content)
{
	FILE *f = fopen(path, "wb");

	if (f == NULL)
		return -1;
	if (fputs(content, f) == EOF) {
		fclose(f);
		return -1;
	}
	fclose(f);
	return 0;
}

/* ---------- PF-01 reader probes ---------- */

static void
test_reader_reject(const char *dir, const char *content, const char *label)
{
	char path[512];
	pid_t out = -12345;
	int rc;

	snprintf(path, sizeof(path), "%s/pf-reader.dat", dir);
	if (write_file(path, content) != 0) {
		printf("FAIL %s:%d: cannot write reader input (%s)\n",
		    __FILE__, __LINE__, label);
		nfails++; nchecks++;
		return;
	}
	rc = rc_read_pidfile(&out, path);
	/* must reject: nonzero return and output left untouched */
	CHECK(rc != 0);
	CHECK(out == -12345);
	if (rc == 0)
		printf("    (probe %-22s OLD-accepted rc=0 out=%ld)\n",
		    label, (long)out);
}

static void
test_reader_accept(const char *dir, const char *content, pid_t want,
    const char *label)
{
	char path[512];
	pid_t out = -12345;
	int rc;

	snprintf(path, sizeof(path), "%s/pf-reader.dat", dir);
	if (write_file(path, content) != 0) {
		printf("FAIL %s:%d: cannot write reader input (%s)\n",
		    __FILE__, __LINE__, label);
		nfails++; nchecks++;
		return;
	}
	rc = rc_read_pidfile(&out, path);
	CHECK(rc == 0);
	CHECK(out == want);
}

static void
run_pf01(const char *dir)
{
	test_reader_reject(dir, "-1\n",          "negative");
	test_reader_reject(dir, "0\n",           "zero");
	test_reader_reject(dir, "123junk\n",     "trailing-junk");
	test_reader_reject(dir,
	    "999999999999999999999999\n",       "24-digit-overflow");
	test_reader_reject(dir, "",              "empty");
	test_reader_reject(dir, "  \t \n",       "whitespace-only");
	test_reader_reject(dir, "+123\n",        "plus-sign");

	test_reader_accept(dir, "12345\n",      12345,       "basic");
	test_reader_accept(dir, "  12345  \n",  12345,       "wrapped-ws");
	/* a positive value <= INT_MAX is accepted regardless of leading zeros */
	test_reader_accept(dir, "000421\n",     421,         "leading-zeros");
}

/* ---------- PF-02 writer sim probes ---------- */

static void
run_pf02(const char *dir)
{
	char path[512];
	char content[64];

	snprintf(path, sizeof(path), "%s/pf-writer.pid", dir);

	/* SHORT: old code returns 0 but publishes only n-1 bytes; fixed code
	 * loops and publishes the whole string. */
	g_sim = SIM_SHORT; g_eintr_left = 0;
	g_monitor_path = path; s_pidfile_fd = -1;
	{
		int rc = rc_make_pidfile(path);

		CHECK(rc == 0);
		if (rc == 0 && file_contents(path, content, sizeof(content)) == 0) {
			char expect[64];
			snprintf(expect, sizeof(expect), "%d\n", (int)getpid());
			CHECK(strcmp(content, expect) == 0);
			if (strcmp(content, expect) != 0)
				printf("    (probe SHORT OLD-published %zu/%zu bytes)\n",
				    strlen(content), strlen(expect));
		}
		rc_cleanup_pidfile();	/* reset static state */
	}

	/* ZERO: 0-length write must be a terminal failure, not success. */
	g_sim = SIM_ZERO; g_eintr_left = 0;
	g_monitor_path = path; s_pidfile_fd = -1;
	{
		int rc = rc_make_pidfile(path);

		CHECK(rc != 0);
		if (rc == 0)
			printf("    (probe ZERO OLD-accepted empty write as success)\n");
		/* terminal cleanup state: nothing pending, file removed */
		CHECK(access(path, F_OK) != 0);
	}

	/* EINTR: old code fails spuriously; fixed code retries to success. */
	g_sim = SIM_EINTR; g_eintr_left = 3;
	g_monitor_path = path; s_pidfile_fd = -1;
	{
		int rc = rc_make_pidfile(path);

		CHECK(rc == 0);
		if (rc == 0) {
			char expect[64];
			snprintf(expect, sizeof(expect), "%d\n", (int)getpid());
			CHECK(file_contents(path, content, sizeof(content)) == 0 &&
			    strcmp(content, expect) == 0);
		} else
			printf("    (probe EINTR OLD-failed spuriously)\n");
		rc_cleanup_pidfile();
	}

	/* EIO: terminal error -> failure, documented cleanup (file removed,
	 * state reset so a later make succeeds). */
	g_sim = SIM_EIO; g_eintr_left = 0;
	g_monitor_path = path; s_pidfile_fd = -1;
	{
		int rc = rc_make_pidfile(path);

		CHECK(rc != 0);
		CHECK(access(path, F_OK) != 0);
		/* state reset: a later make must succeed (no leaked lock/fd) */
		g_sim = SIM_NONE;
		g_monitor_path = path; s_pidfile_fd = -1;
		CHECK(rc_make_pidfile(path) == 0);
		rc_cleanup_pidfile();
	}
}

/* ---------- PF-04 oversize progname ---------- */

static long
dir_entry_count(const char *dir)
{
	DIR *d = opendir(dir);
	struct dirent *e;
	long n = 0;

	if (d == NULL)
		return -1;
	while ((e = readdir(d)) != NULL)
		if (e->d_name[0] != '.')
			n++;
	closedir(d);
	return n;
}

static void
run_pf04(const char *dir)
{
	char *big = malloc(PATH_MAX + 128);
	char sane_path[512];
	long before, after;
	int rc;

	CHECK(big != NULL);
	if (big == NULL)
		return;
	memset(big, 'a', PATH_MAX + 64);
	big[PATH_MAX + 64] = '\0';

	/* an oversized progname must be rejected BEFORE any open, so no
	 * truncated-named pidfile is ever created. */
	before = dir_entry_count(dir);
	g_sim = SIM_NONE; g_monitor_path = NULL;
	rc = rc_make_pidfile_on_dir(dir, big);

	CHECK(rc != 0);
	if (rc == 0) {
		/* old code ignored the snprintf return and created a
		 * truncated-named file: prove it (red). */
		after = dir_entry_count(dir);
		printf("    (probe PF-04 OLD-truncated: dir entries %ld -> %ld)\n",
		    before, after);
		CHECK(after == before);
	}
	/* release any truncated-file state a (red) build left behind */
	rc_cleanup_pidfile();

	/* sanity: a normal-length progname still works, ends in ".pid", and
	 * the second-make rejection (pidfile.c:66-70) still holds. */
	snprintf(sane_path, sizeof(sane_path), "%s/sane.pid", dir);
	rc = rc_make_pidfile_on_dir(dir, "sane");
	CHECK(rc == 0);
	CHECK(access(sane_path, F_OK) == 0);
	CHECK(rc_make_pidfile_on_dir(dir, "sane") != 0);	/* 2nd-make reject */
	rc_cleanup_pidfile();
	free(big);
}

/* ---------- PF-05 CLOEXEC ---------- */

static void
run_pf05(const char *dir)
{
	char path[512];
	int st;

	snprintf(path, sizeof(path), "%s/pf-p05.pid", dir);

	g_sim = SIM_NONE; g_monitor_path = path; s_pidfile_fd = -1;
	if (rc_make_pidfile(path) != 0) {
		printf("FAIL %s:%d: cannot make pidfile\n", __FILE__, __LINE__);
		nfails++; nchecks++;
		return;
	}

	/* direct check: the writer fd must be close-on-exec */
	{
		int fl = fcntl(s_pidfile_fd, F_GETFD);

		CHECK(fl != -1 && (fl & FD_CLOEXEC) != 0);
		if (fl != -1 && !(fl & FD_CLOEXEC))
			printf("    (probe PF-05 OLD: fd NOT close-on-exec)\n");
	}

	/* behavioral check: fork+exec a helper holding the inherited fd; the
	 * daemon (parent) drops ITS OWN copy, leaving only the helper's
	 * inherited copy.  The re-exec'd helper tries to take the flock:
	 *   - fixed (CLOEXEC): exec closed the inherited fd -> flock free,
	 *     helper acquires it -> status 0.
	 *   - old (no CLOEXEC): helper's inherited fd keeps the flock alive ->
	 *     flock busy -> helper status 1. */
	{
		pid_t pid = fork();

		if (pid < 0) {
			CHECK(0);
		} else if (pid == 0) {
			/* helper: wait for parent to drop its copy, then exec */
			sleep(1);
			execl("/proc/self/exe", "pidfile_test",
			    "--flockcheck", path, (char *)NULL);
			_exit(99);	/* exec failed */
		} else {
			/* daemon drops its own copy (abrupt death) */
			close(s_pidfile_fd);
			s_pidfile_fd = -1;
			if (waitpid(pid, &st, 0) != pid) {
				CHECK(0);
				return;
			}
			if (WIFEXITED(st))
				CHECK(WEXITSTATUS(st) == 0);
			else
				CHECK(0);
			if (WIFEXITED(st) && WEXITSTATUS(st) != 0)
				printf("    (probe PF-05 OLD: flock prolonged "
				    "by exec'd helper, status=%d)\n",
				    WEXITSTATUS(st));
		}
	}
}

/* ---------- flockcheck mode (re-exec target) ---------- */

static int
do_flockcheck(const char *path)
{
	int fd = open(path, O_RDWR);
	int r;

	if (fd < 0)
		return 2;
	r = flock(fd, LOCK_EX | LOCK_NB);
	close(fd);
	return r == 0 ? 0 : 1;
}

int
main(int argc, char **argv)
{
	char dir[] = "/tmp/pfXXXXXX";

	if (argc >= 3 && strcmp(argv[1], "--flockcheck") == 0)
		return do_flockcheck(argv[2]);

	if (mkdtemp(dir) == NULL) {
		printf("FAIL: mkdtemp\n");
		return 1;
	}

	/* red-before target: this label is printed by helper scripts and by
	 * the green run to mark the harness; see the TDD evidence. */
	printf("=== pidfile_test (PF) begin ===\n");
	run_pf01(dir);
	run_pf02(dir);
	run_pf04(dir);
	run_pf05(dir);
	printf("TOTAL checks=%d fails=%d\n", nchecks, nfails);

	return nfails != 0 ? 1 : 0;
}
