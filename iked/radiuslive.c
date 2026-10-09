/*
 * radiuslive.c - LIVE round-trip harness for the iked RADIUS client.
 *
 * Drives ikev2_radius_exchange() against a real FreeRADIUS on
 * 127.0.0.1:1812 using the shared secret from /etc/racoon2/radius-secret.
 * Sends an EAP Identity response and prints the Access-* reply code + the
 * server's EAP-Message / State back to the caller.  The secret is read
 * from the file at runtime (never from the command line).
 *
 * This is the reviewer-gated proof that the RADIUS client transport (UDP,
 * Message-Authenticator, BADVERIFY, State) actually speaks a live server,
 * before it is wired into the IKE_AUTH responder.
 */
#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "racoon.h"
#include "gcmalloc.h"
#include "vmbuf.h"
#include "ikev2_radius.h"

int
main(int argc, char **argv)
{
	const char *secret_path = argc > 1 ? argv[1] : "/etc/racoon2/radius-secret";
	const char *ident = argc > 2 ? argv[2] : "radiuslocal";
	FILE *fp;
	rc_vchar_t secret, *eap, *got;
	struct sockaddr_in server;
	struct ikev2_radius_opt opt;
	struct ikev2_radius_response *resp = NULL;
	uint8_t id = 1;
	uint8_t eap_ident[256];
	size_t idlen;
	int rc, rv;

	if (rbuf_init(8, 80, 8, 1000, 5))
		return 2;

	fp = fopen(secret_path, "r");
	if (!fp) {
		perror("open secret");
		return 2;
	}
	secret.v = malloc(256);
	secret.l = fread(secret.v, 1, 255, fp);
	fclose(fp);
	if (secret.l == 0) {
		fprintf(stderr, "empty secret file\n");
		return 2;
	}
	/* strip trailing newline/space */
	while (secret.l && (((uint8_t *)secret.v)[secret.l - 1] == '\n' ||
			   ((uint8_t *)secret.v)[secret.l - 1] == '\r' ||
			   ((uint8_t *)secret.v)[secret.l - 1] == ' '))
		secret.l--;

	/* EAP Identity Response: Code=2, Id=1, Len, Type=1, identity bytes */
	idlen = strlen(ident);
	if (idlen > 251)
		idlen = 251;
	eap_ident[0] = 2;			/* Response */
	eap_ident[1] = 1;			/* identifier */
	eap_ident[2] = (uint8_t)((5 + idlen) >> 8);
	eap_ident[3] = (uint8_t)((5 + idlen) & 0xff);
	eap_ident[4] = 1;			/* Type = Identity */
	memcpy(eap_ident + 5, ident, idlen);

	eap = rc_vmalloc(5 + idlen);
	if (!eap)
		return 2;
	memcpy(eap->v, eap_ident, 5 + idlen);
	eap->l = 5 + idlen;

	memset(&server, 0, sizeof(server));
	server.sin_family = AF_INET;
	server.sin_port = htons(1812);
	inet_pton(AF_INET, "127.0.0.1", &server.sin_addr);

	memset(&opt, 0, sizeof(opt));
	opt.secret = &secret;
	opt.user_name = ident;
	opt.nas_ip = "127.0.0.1";
	opt.retries = 2;
	opt.timeout_ms = 3000;

	rv = ikev2_radius_exchange((struct sockaddr *)&server,
				   (socklen_t)sizeof(server),
				   eap, &opt, &id, &resp);

	printf("exchange rc=%d (0=OK 1=n/a %d=TIMEOUT %d=BADVERIFY)\n",
	       rv, IKEV2_RADIUS_TIMEOUT, IKEV2_RADIUS_BADVERIFY);
	if (rv == IKEV2_RADIUS_OK && resp) {
		const char *code =
			resp->code == IKEV2_RADIUS_CODE_ACCESS_ACCEPT ? "Access-Accept" :
			resp->code == IKEV2_RADIUS_CODE_ACCESS_REJECT ? "Access-Reject" :
			resp->code == IKEV2_RADIUS_CODE_ACCESS_CHALLENGE ? "Access-Challenge" : "?";
		printf("reply code=%u (%s)\n", resp->code, code);
		got = ikev2_radius_eap_message(resp);
		if (got) {
			const uint8_t *gv = (const uint8_t *)got->v;
			printf("EAP-Message (%zu bytes):", got->l);
			for (rc = 0; rc < (int)got->l; rc++)
				printf(" %02x", (unsigned char)gv[rc]);
			printf("\n");
			if (got->l >= 5)
				printf("EAP type=%u\n", (unsigned char)gv[4]);
			rc_vfree(got);
		}
		got = ikev2_radius_find_attr(resp, IKEV2_RADIUS_ATTR_STATE);
		if (got)
			printf("State attr (%zu bytes) present - multi-round OK\n",
			       got->l);
		ikev2_radius_response_free(resp);
	}
	rc_vfree(eap);
	free(secret.v);
	return rv == IKEV2_RADIUS_OK ? 0 : 1;
}
