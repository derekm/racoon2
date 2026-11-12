/* $Id: pidfile.c,v 1.3 2006/06/23 11:01:50 kamada Exp $ */
/*
 * Copyright (C) 2006 WIDE Project.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/param.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "plog.h"
#include "pidfile.h"

static char *pidfile = NULL;
static int pidfile_fd = -1;

int
rc_make_pidfile_on_dir(const char *dirname, const char *progname)
{
	char filename[PATH_MAX];
	int n;

	/* PF-04: an oversized progname must fail BEFORE any open() so a
	 * truncated-named pidfile is never created. */
	n = snprintf(filename, sizeof(filename), "%s/%s.pid",
	    dirname, progname);
	if (n < 0 || n >= (int)sizeof(filename)) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		    "path too long for pid file: %s/%s.pid\n",
		    dirname, progname);
		return -1;
	}
	return rc_make_pidfile(filename);
}

int
rc_make_pidfile(const char *filename)
{
	char pidstr[16];
	pid_t pid;
	int n;

	if (pidfile != NULL || pidfile_fd != -1) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		    "make_pidfile() is called twice\n");
		return -1;
	}

	pid = getpid();
	if ((pidfile = strdup(filename)) == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL, "out of memory\n");
		return -1;
	}

	/* PF-05: the pidfile fd is intentionally close-on-exec so that the
	 * short-lived helpers iked forks+execs (script.c, addketest.c)
	 * cannot keep the flock on the pidfile alive after an abrupt death:
	 * the daemon's own fd is the ONLY one that must hold the lock, and
	 * exec'ing a helper must release it.  (Residual, intentionally left
	 * unchanged: spmd/signal.c:97 does a separate unconditional
	 * unlink(SPMD_PID_FILE) from the signal handler, bypassing the
	 * dev/ino safeguard below; that signal-handler path is not touched
	 * here.) */
#ifdef O_CLOEXEC
	if ((pidfile_fd = open(pidfile,
	    O_WRONLY | O_CREAT | O_CLOEXEC, 0644)) == -1) {
#else
	if ((pidfile_fd = open(pidfile, O_WRONLY | O_CREAT, 0644)) == -1) {
#endif
		plog(PLOG_INTERR, PLOGLOC, NULL,
		    "%s: open: %s\n", pidfile, strerror(errno));
		goto fail;
	}
#ifndef O_CLOEXEC
	/* portable fallback when O_CLOEXEC is not available at open */
	if (fcntl(pidfile_fd, F_SETFD, FD_CLOEXEC) == -1) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		    "%s: fcntl(FD_CLOEXEC): %s\n",
		    pidfile, strerror(errno));
		goto fail;
	}
#endif
	/* Truncation stays AFTER the lock is taken (never before): we must
	 * not truncate a file whose flock we do not yet own. */
	if (flock(pidfile_fd, LOCK_EX | LOCK_NB) == -1) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		    "%s: flock: %s\n", pidfile, strerror(errno));
		goto fail;
	}
	if (ftruncate(pidfile_fd, 0) == -1) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		    "%s: ftruncate: %s\n", pidfile, strerror(errno));
		rc_cleanup_pidfile();
		return -1;
	}
	/* pid_t == int on Linux/BSD/Solaris; %d of getpid() can never
	 * overflow pidstr[16], but verify the snprintf result anyway.  The
	 * text ends with '\n', matching the reader's newline policy. */
	n = snprintf(pidstr, sizeof(pidstr), "%d\n", (int)pid);
	if (n < 0 || n >= (int)sizeof(pidstr)) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		    "snprintf pid string failed\n");
		rc_cleanup_pidfile();
		return -1;
	}
	/* PF-02: success must imply COMPLETE publication of the whole
	 * pidstring.  Loop over write(), retrying on EINTR and continuing
	 * on partial (short) writes until every byte is written.  A
	 * terminal error (-1 other than EINTR, or a persistent 0-length
	 * write) is a failure and follows the documented cleanup path,
	 * preserving the existing file/state + lock ownership semantics. */
	{
		size_t left = (size_t)strlen(pidstr);
		const char *p = pidstr;

		while (left > 0) {
			ssize_t w = write(pidfile_fd, p, left);

			if (w == -1) {
				if (errno == EINTR)
					continue;
				plog(PLOG_INTERR, PLOGLOC, NULL,
				    "%s: write: %s\n",
				    pidfile, strerror(errno));
				rc_cleanup_pidfile();
				return -1;
			}
			if (w == 0) {
				/* persistent zero-length write is terminal */
				plog(PLOG_INTERR, PLOGLOC, NULL,
				    "%s: write returned 0\n", pidfile);
				rc_cleanup_pidfile();
				return -1;
			}
			p += w;
			left -= (size_t)w;
		}
	}

	return 0;

fail:
	/* Unlike rc_cleanup_pidfile(), this will never unlink the file. */
	if (pidfile_fd != -1) {
		close(pidfile_fd);
		pidfile_fd = -1;
	}
	free(pidfile);
	pidfile = NULL;
	return -1;
}

void
rc_cleanup_pidfile(void)
{
	struct stat sb1, sb2;

	if (pidfile == NULL && pidfile_fd == -1)
		return;
	if (pidfile == NULL || pidfile_fd == -1) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		    "inconsistent PID file info\n");
		return;
	}

	/* NB: race between stat() and unlink() */
	if (fstat(pidfile_fd, &sb1) == -1)
		plog(PLOG_INTWARN, PLOGLOC, NULL,
		    "fstat PID file failed: %s\n", strerror(errno));
	else if (stat(pidfile, &sb2) == -1)
		plog(PLOG_INTWARN, PLOGLOC, NULL,
		    "%s: stat: %s\n", pidfile, strerror(errno));
	else if (sb1.st_dev != sb2.st_dev || sb1.st_ino != sb2.st_ino)
		plog(PLOG_INTWARN, PLOGLOC, NULL,
		    "PID file is replaced; exiting without unlinking it\n");
	else {
		if (unlink(pidfile) == -1)
			plog(PLOG_INTERR, PLOGLOC, NULL,
			    "%s: unlink: %s\n", pidfile, strerror(errno));
	}

	free(pidfile);
	pidfile = NULL;
	close(pidfile_fd);
	pidfile_fd = -1;
}

int
rc_read_pidfile(pid_t *pid, const char *filename)
{
	char buf[64];
	int fd;
	ssize_t ret;
	unsigned long val = 0;
	int ndigits = 0;
	char *p;

	fd = open(filename, O_RDONLY, 0);
	if (fd == -1) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		    "%s: open: %s\n", filename, strerror(errno));
		return -1;
	}
	ret = read(fd, buf, sizeof(buf));
	if (ret == -1) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		    "%s: read: %s\n", filename, strerror(errno));
		close(fd);
		return -1;
	}
	if (ret == (ssize_t)sizeof(buf)) {
		/* A valid pid (<= 10 digits + newline) is tiny; anything
		 * that fills the whole buffer may be overlong - probe for
		 * more data and reject if the file is larger. */
		char c;

		if (read(fd, &c, 1) > 0) {
			plog(PLOG_INTERR, PLOGLOC, NULL,
			    "%s: pid file too large\n", filename);
			close(fd);
			return -1;
		}
	}
	close(fd);
	buf[ret] = '\0';

	/* Policy (PF-01): the output must be a positive individual-process
	 * PID, so a tampered pidfile can never become a process-group or
	 * signal-all target at the consumers.  The whole file must parse as
	 * exactly one positive decimal integer in [1, INT_MAX] (pid_t ==
	 * int; Linux pid_max 4194304 < INT_MAX) optionally surrounded by
	 * ASCII whitespace (spaces/tabs/newlines) - a single trailing
	 * newline is accepted, as is leading/trailing whitespace.  Empty
	 * text, nonnumeric input, zero, negatives, signs, trailing junk
	 * (e.g. "123junk"), overflow past INT_MAX, and overlong files are
	 * all REJECTED.  A range-checked digit parse is used (never %d,
	 * whose glibc clamp would mask overflow).  On rejection the output
	 * parameter is left untouched and nonzero is returned. */
	p = buf;
	while (*p != '\0' && isspace((unsigned char)*p))
		p++;
	for (; *p != '\0' && isdigit((unsigned char)*p); p++) {
		unsigned int d = (unsigned int)(*p - '0');

		if (val > ((unsigned long)INT_MAX - (unsigned long)d) / 10UL)
			return -1;	/* overflow past INT_MAX */
		val = val * 10UL + (unsigned long)d;
		ndigits++;
	}
	while (*p != '\0' && isspace((unsigned char)*p))
		p++;
	if (ndigits == 0 || *p != '\0')
		return -1;
	if (val == 0 || val > (unsigned long)INT_MAX)
		return -1;
	*pid = (pid_t)val;
	return 0;
}
