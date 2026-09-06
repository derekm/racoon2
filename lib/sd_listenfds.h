/* $Id$ */
/*
 * systemd LISTEN_FDS helper. No libsystemd dependency.
 * Copyright (C) 2026 racoon2 contributors. Same BSD license as libracoon.
 */
#ifndef _RC_SD_LISTENFDS_H
#define _RC_SD_LISTENFDS_H

#define RC_LISTEN_FDS_START	3

/* Number of fds passed by systemd, or 0 if not socket-activated. */
int rc_listenfds(void);

/*
 * Consume one inherited fd matching family + socktype.
 * port_host is host-order UDP/TCP port; 0 matches any (unix).
 * Returns fd, or -1 if none left.
 */
int rc_take_listenfd(int family, int socktype, int port_host);

#endif
