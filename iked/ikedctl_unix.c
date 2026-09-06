/*
 * Linux ikedctl: unix admin_com client. Not a KM backend.
 * Kernel SAD/SPD: ip xfrm. This talks IKE SAs only.
 */
#include <config.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <err.h>
#include <time.h>

#include "admin.h"

const char *adminsock_path = ADMINSOCK_PATH;

/* Keep in sync with ikev1/handler.h struct ph1dump. */
struct wire_ph1dump {
	uint8_t i_ck[8];
	uint8_t r_ck[8];
	int status;
	int side;
	struct sockaddr_storage remote;
	struct sockaddr_storage local;
	uint8_t version;
	uint8_t etype;
	time_t created;
	int ph2cnt;
};

static int so = -1;

static void
usage(const char *p)
{
	fprintf(stderr,
"Usage:\n"
"  %s [-s socket] reload-config\n"
"  %s [-s socket] show-sa isakmp\n"
"  %s [-s socket] flush-sa isakmp\n"
"  %s [-s socket] establish-sa isakmp inet <src> <dst> [selector_index]\\n"
"  %s [-s socket] vpn-connect <gateway>\n"
"  %s [-s socket] vpn-disconnect <gateway>\n"
"\n"
"esp/ah SAD: ip xfrm state / ip xfrm policy\n",
		p, p, p, p, p, p);
	exit(EXIT_FAILURE);
}

static int
com_init(void)
{
	struct sockaddr_un sun;

	so = socket(AF_UNIX, SOCK_STREAM, 0);
	if (so < 0)
		err(EXIT_FAILURE, "socket");
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", adminsock_path);
	if (connect(so, (struct sockaddr *)&sun, sizeof(sun)) < 0)
		err(EXIT_FAILURE, "connect %s", adminsock_path);
	return 0;
}

static int
com_send(const void *buf, size_t len)
{
	const char *p = buf;
	size_t sent = 0;
	ssize_t n;

	while (sent < len) {
		n = send(so, p + sent, len - sent, 0);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			err(EXIT_FAILURE, "send");
		}
		if (n == 0)
			errx(EXIT_FAILURE, "send: short write");
		sent += (size_t)n;
	}
	return 0;
}

static void *
com_recv(size_t *outlen)
{
	struct admin_com hdr;
	char *buf;
	size_t tlen, got = 0;
	ssize_t n;

	n = recv(so, &hdr, sizeof(hdr), MSG_PEEK);
	if (n < 0 || (size_t)n < sizeof(hdr))
		errx(EXIT_FAILURE, "recv header");
	if (hdr.ac_cmd & ADMIN_FLAG_LONG_REPLY)
		tlen = ((uint32_t)hdr.ac_len) +
			(((uint32_t)hdr.ac_len_high) << 16);
	else
		tlen = hdr.ac_len;
	if (tlen < sizeof(hdr))
		errx(EXIT_FAILURE, "short admin reply");
	buf = malloc(tlen);
	if (!buf)
		err(EXIT_FAILURE, "malloc");
	while (got < tlen) {
		n = recv(so, buf + got, tlen - got, 0);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			err(EXIT_FAILURE, "recv");
		}
		if (n == 0)
			errx(EXIT_FAILURE, "recv: eof");
		got += (size_t)n;
	}
	*outlen = tlen;
	return buf;
}

static void *
make_req(uint16_t cmd, uint16_t proto, size_t extra, size_t *len)
{
	struct admin_com *h;
	char *buf;

	*len = sizeof(*h) + extra;
	buf = calloc(1, *len);
	if (!buf)
		err(EXIT_FAILURE, "calloc");
	h = (struct admin_com *)buf;
	h->ac_len = (u_int16_t)*len;
	h->ac_cmd = ADMIN_FLAG_VERSION | cmd;
	h->ac_version = 1;
	h->ac_proto = proto;
	return buf;
}

static void
fill_index(struct admin_com_indexes *ndx, int family,
	   const char *src, const char *dst)
{
	struct sockaddr_in *s4, *d4;
	struct sockaddr_in6 *s6, *d6;

	memset(ndx, 0, sizeof(*ndx));
	if (family == AF_INET) {
		s4 = (struct sockaddr_in *)&ndx->src;
		d4 = (struct sockaddr_in *)&ndx->dst;
		s4->sin_family = AF_INET;
		d4->sin_family = AF_INET;
		if (inet_pton(AF_INET, src, &s4->sin_addr) != 1)
			errx(EXIT_FAILURE, "bad src %s", src);
		if (inet_pton(AF_INET, dst, &d4->sin_addr) != 1)
			errx(EXIT_FAILURE, "bad dst %s", dst);
	} else {
		s6 = (struct sockaddr_in6 *)&ndx->src;
		d6 = (struct sockaddr_in6 *)&ndx->dst;
		s6->sin6_family = AF_INET6;
		d6->sin6_family = AF_INET6;
		if (inet_pton(AF_INET6, src, &s6->sin6_addr) != 1)
			errx(EXIT_FAILURE, "bad src %s", src);
		if (inet_pton(AF_INET6, dst, &d6->sin6_addr) != 1)
			errx(EXIT_FAILURE, "bad dst %s", dst);
	}
}

static void
print_sa(const char *payload, size_t len)
{
	const struct wire_ph1dump *pd;
	char host[NI_MAXHOST];
	unsigned i;

	if (len % sizeof(*pd)) {
		warnx("show-sa: payload %zu not a multiple of %zu",
		      len, sizeof(*pd));
	}
	printf("Destination            Cookies                           V  S  ST P2\n");
	pd = (const struct wire_ph1dump *)payload;
	while (len >= sizeof(*pd)) {
		if (getnameinfo((struct sockaddr *)&pd->remote,
				sizeof(pd->remote), host, sizeof(host),
				NULL, 0, NI_NUMERICHOST) != 0)
			snprintf(host, sizeof(host), "?");
		printf("%-22s ", host);
		for (i = 0; i < 8; i++)
			printf("%02x", pd->i_ck[i]);
		printf(":");
		for (i = 0; i < 8; i++)
			printf("%02x", pd->r_ck[i]);
		printf(" %02x %c  %2d %d\n",
		       pd->version,
		       pd->side == 0 ? 'I' : 'R',
		       pd->status, pd->ph2cnt);
		pd++;
		len -= sizeof(*pd);
	}
}

static void
transact(void *req, size_t reqlen)
{
	struct admin_com *rep;
	size_t replen;
	int errn;

	com_send(req, reqlen);
	rep = com_recv(&replen);
	errn = rep->ac_errno;
	if (errn) {
		if (errn == ENOTSUP)
			errx(EXIT_FAILURE,
			     "not supported (esp/ah: ip xfrm; %s)",
			     strerror(errn));
		errx(EXIT_FAILURE, "%s", strerror(errn));
	}
	if ((rep->ac_cmd & ~ADMIN_FLAG_LONG_REPLY) == ADMIN_SHOW_SA)
		print_sa((char *)(rep + 1),
			 replen > sizeof(*rep) ? replen - sizeof(*rep) : 0);
	free(rep);
	free(req);
}

static char *
local_for(const char *dst, int *af)
{
	struct addrinfo hints, *res;
	int fd;
	struct sockaddr_storage ss;
	socklen_t slen = sizeof(ss);
	static char host[NI_MAXHOST];

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_DGRAM;
	if (getaddrinfo(dst, "500", &hints, &res) != 0)
		errx(EXIT_FAILURE, "cannot resolve %s", dst);
	*af = res->ai_family;
	fd = socket(res->ai_family, SOCK_DGRAM, 0);
	if (fd < 0)
		err(EXIT_FAILURE, "socket");
	if (connect(fd, res->ai_addr, res->ai_addrlen) < 0)
		err(EXIT_FAILURE, "connect");
	if (getsockname(fd, (struct sockaddr *)&ss, &slen) < 0)
		err(EXIT_FAILURE, "getsockname");
	close(fd);
	freeaddrinfo(res);
	if (getnameinfo((struct sockaddr *)&ss, slen, host, sizeof(host),
			NULL, 0, NI_NUMERICHOST) != 0)
		errx(EXIT_FAILURE, "local address");
	return host;
}

int
main(int ac, char **av)
{
	const char *cmd;
	void *req;
	size_t reqlen;
	int c;
	const char *pname = av[0];

	while ((c = getopt(ac, av, "s:")) != -1) {
		switch (c) {
		case 's':
			adminsock_path = optarg;
			break;
		default:
			usage(pname);
		}
	}
	ac -= optind;
	av += optind;
	if (ac < 1)
		usage(pname);
	cmd = av[0];
	ac--;
	av++;

	if ((strcmp(cmd, "show-sa") == 0 || strcmp(cmd, "ss") == 0) &&
	    ac == 1 && (strcmp(av[0], "esp") == 0 ||
			strcmp(av[0], "ah") == 0 ||
			strcmp(av[0], "ipsec") == 0))
		errx(EXIT_FAILURE, "kernel SAD: ip -s xfrm state");
	if ((strcmp(cmd, "flush-sa") == 0 || strcmp(cmd, "fs") == 0) &&
	    ac == 1 && (strcmp(av[0], "esp") == 0 ||
			strcmp(av[0], "ah") == 0 ||
			strcmp(av[0], "ipsec") == 0))
		errx(EXIT_FAILURE, "kernel SAD: ip xfrm state flush");

	com_init();

	if (strcmp(cmd, "reload-config") == 0 || strcmp(cmd, "rc") == 0) {
		req = make_req(ADMIN_RELOAD_CONF, 0, 0, &reqlen);
		transact(req, reqlen);
	} else if (strcmp(cmd, "show-sa") == 0 || strcmp(cmd, "ss") == 0) {
		if (ac != 1 || strcmp(av[0], "isakmp") != 0) {
			if (ac == 1 && (strcmp(av[0], "esp") == 0 ||
					strcmp(av[0], "ah") == 0 ||
					strcmp(av[0], "ipsec") == 0))
				errx(EXIT_FAILURE,
				     "kernel SAD: ip -s xfrm state");
			usage(pname);
		}
		req = make_req(ADMIN_SHOW_SA, ADMIN_PROTO_ISAKMP, 0, &reqlen);
		transact(req, reqlen);
	} else if (strcmp(cmd, "flush-sa") == 0 || strcmp(cmd, "fs") == 0) {
		if (ac != 1 || strcmp(av[0], "isakmp") != 0) {
			if (ac == 1 && (strcmp(av[0], "esp") == 0 ||
					strcmp(av[0], "ah") == 0 ||
					strcmp(av[0], "ipsec") == 0))
				errx(EXIT_FAILURE,
				     "kernel SAD: ip xfrm state flush");
			usage(pname);
		}
		req = make_req(ADMIN_FLUSH_SA, ADMIN_PROTO_ISAKMP, 0, &reqlen);
		transact(req, reqlen);
	} else if (strcmp(cmd, "establish-sa") == 0 ||
		   strcmp(cmd, "es") == 0) {
		struct admin_com_indexes *ndx;
		const char *fam, *src, *dst, *name = NULL;
		size_t extra;
		int af;

		if (ac < 4 || strcmp(av[0], "isakmp") != 0)
			usage(pname);
		fam = av[1];
		src = av[2];
		dst = av[3];
		if (ac >= 5)
			name = av[4];
		if (strcmp(fam, "inet") == 0)
			af = AF_INET;
		else if (strcmp(fam, "inet6") == 0)
			af = AF_INET6;
		else
			usage(pname);
		extra = sizeof(*ndx) + (name ? strlen(name) + 1 : 0);
		req = make_req(ADMIN_ESTABLISH_SA, ADMIN_PROTO_ISAKMP,
			       extra, &reqlen);
		ndx = (struct admin_com_indexes *)
			((char *)req + sizeof(struct admin_com));
		fill_index(ndx, af, src, dst);
		if (name)
			memcpy((char *)(ndx + 1), name, strlen(name) + 1);
		transact(req, reqlen);
	} else if (strcmp(cmd, "vpn-connect") == 0 ||
		   strcmp(cmd, "vc") == 0) {
		char *src;
		struct admin_com_indexes *ndx;
		int af;

		if (ac < 1)
			usage(pname);
		src = local_for(av[0], &af);
		req = make_req(ADMIN_ESTABLISH_SA, ADMIN_PROTO_ISAKMP,
			       sizeof(*ndx), &reqlen);
		ndx = (struct admin_com_indexes *)
			((char *)req + sizeof(struct admin_com));
		fill_index(ndx, af, src, av[0]);
		transact(req, reqlen);
	} else if (strcmp(cmd, "vpn-disconnect") == 0 ||
		   strcmp(cmd, "vd") == 0) {
		struct admin_com_indexes *ndx;
		int af;
		const char *src;

		if (ac < 1)
			usage(pname);
		(void)local_for(av[0], &af);
		src = (af == AF_INET6) ? "::" : "0.0.0.0";
		req = make_req(ADMIN_DELETE_ALL_SA_DST, ADMIN_PROTO_ISAKMP,
			       sizeof(*ndx), &reqlen);
		ndx = (struct admin_com_indexes *)
			((char *)req + sizeof(struct admin_com));
		fill_index(ndx, af, src, av[0]);
		transact(req, reqlen);
	} else {
		usage(pname);
	}
	close(so);
	return EXIT_SUCCESS;
}
