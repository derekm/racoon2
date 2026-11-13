/*
 * safefile_test - exercises lib/safefile.c rc_safefile()/rc_privatedir()
 * validation against disposable temp fixtures only (never a live config file).
 *
 * It asserts the secure-behaviour contract (SF-01): with ENABLE_SECURE active,
 * a world-readable secret is REJECTED (rc 5), a foreign-owner file REJECTED
 * (rc 2), a non-regular target REJECTED (rc 3), a public/loose non-secret
 * ACCEPTED (sec=0, intended), and rc_privatedir rejects a 0777 dir while
 * accepting 0700.
 *
 * Compile-time wiring is conveyed to this TU by the SAME config.h define that
 * gates safefile.c: on a secure (default) build ENABLE_SECURE is present and
 * the full assertions run.  The build-wiring itself is separately asserted by
 * the CI/configure grep (lib/config.h defines ENABLE_SECURE and the
 * safefile.lo compile line carries -DENABLE_SECURE).  When ENABLE_SECURE is
 * genuinely off (--disable-secure documented opt-out) this test SKIPs so the
 * opt-out build keeps a clean `make check`.
 *
 * The foreign-owner subtest needs euid 0 to chown() to a different uid; when
 * unavailable it reports SKIP rather than failing.
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "safefile.h"

#define OTHER_UID 65534		/* nobody; must differ from getuid() */

static int failures;
static int skips;

static int
touch_file(const char *path, mode_t mode)
{
	int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, mode);

	if (fd < 0) {
		perror(path);
		return -1;
	}
	if (chmod(path, mode) != 0) {
		perror("chmod");
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

static void
check(const char *name, int want, int got)
{
	if (want == got) {
		printf("PASS %-40s rc=%d\n", name, got);
	} else {
		printf("FAIL %-40s want=%d got=%d\n", name, want, got);
		failures++;
	}
}

#ifdef ENABLE_SECURE
static int
run_secure_tests(void)
{
	char dir[] = "/tmp/r2safefileXXXXXX";
	char secret_ok[512], secret_world[512], foreign[512], nonreg[512];
	char pub_ok[512], pub_wr[512], priv_ok[512], priv_loose[512];
	uid_t me = getuid();

	umask(0);
	if (mkdtemp(dir) == NULL) {
		perror("mkdtemp");
		return 2;
	}

	/* secure secret files */
	snprintf(secret_ok, sizeof secret_ok, "%s/secret_ok", dir);
	snprintf(secret_world, sizeof secret_world, "%s/secret_world", dir);
	snprintf(foreign, sizeof foreign, "%s/foreign", dir);
	snprintf(nonreg, sizeof nonreg, "%s/nonreg", dir);

	if (touch_file(secret_ok, 0600) < 0 ||
	    touch_file(secret_world, 0644) < 0 ||
	    touch_file(foreign, 0600) < 0 ||
	    mkdir(nonreg, 0700) != 0) {
		fprintf(stderr, "fixture setup failed\n");
		return 2;
	}

	/* owner-only regular secret -> accept */
	check("safefile secret 0600", RC_SAFEFILE_SAFE, rc_safefile(secret_ok, 1));
	/* world-readable secret -> reject RC_SAFEFILE_PERMISSION (5) */
	check("safefile secret 0644", RC_SAFEFILE_PERMISSION, rc_safefile(secret_world, 1));
	/* non-regular target -> reject RC_SAFEFILE_NOTREG (3) */
	check("safefile non-regular", RC_SAFEFILE_NOTREG, rc_safefile(nonreg, 1));

	/* foreign owner -> reject RC_SAFEFILE_OWNER (2): needs euid 0 */
	if (me == 0) {
		if (chown(foreign, OTHER_UID, OTHER_UID) != 0) {
			perror("chown");
			skips++;
		} else {
			check("safefile foreign-owner", RC_SAFEFILE_OWNER,
			      rc_safefile(foreign, 1));
		}
	} else {
		printf("SKIP %-40s (needs euid 0 to chown)\n", "safefile foreign-owner");
		skips++;
	}

	/*
	 * non-secret files: public readability / group+other-write are ACCEPTED
	 * for sec=0 (the permission gate is intentionally secret-only).
	 */
	snprintf(pub_ok, sizeof pub_ok, "%s/pub_ok", dir);
	snprintf(pub_wr, sizeof pub_wr, "%s/pub_wr", dir);
	if (touch_file(pub_ok, 0644) < 0 || touch_file(pub_wr, 0666) < 0) {
		fprintf(stderr, "fixture setup failed\n");
		return 2;
	}
	check("safefile public 0644 sec=0", RC_SAFEFILE_SAFE, rc_safefile(pub_ok, 0));
	check("safefile group/other-wr 0666 sec=0", RC_SAFEFILE_SAFE,
	      rc_safefile(pub_wr, 0));

	/* rc_privatedir: 0700 accept, 0777 reject RC_SAFEFILE_PERMISSION (5) */
	snprintf(priv_ok, sizeof priv_ok, "%s/priv_ok", dir);
	snprintf(priv_loose, sizeof priv_loose, "%s/priv_loose", dir);
	if (mkdir(priv_ok, 0700) != 0 || mkdir(priv_loose, 0777) != 0) {
		perror("mkdir");
		return 2;
	}
	check("privatedir 0700", RC_SAFEFILE_SAFE, rc_privatedir(priv_ok));
	check("privatedir 0777", RC_SAFEFILE_PERMISSION, rc_privatedir(priv_loose));

	/* teardown */
	unlink(secret_ok);
	unlink(secret_world);
	unlink(foreign);
	unlink(pub_ok);
	unlink(pub_wr);
	rmdir(nonreg);
	rmdir(priv_ok);
	rmdir(priv_loose);
	rmdir(dir);

	return failures != 0 ? 1 : 0;
}
#else  /* !ENABLE_SECURE */
static int
run_secure_tests(void)
{
	(void)skips;
	printf("SKIP safefile_test: ENABLE_SECURE not defined "
	       "(--disable-secure opt-out or missing build wiring)\n");
	return 0;
}
#endif

int
main(void)
{
	if (run_secure_tests() != 0)
		return 1;
	printf("safefile_test: %d failed, %d skipped\n", failures, skips);
	return 0;
}
