/* RFC 6290 Quick Crash Detection. Token maker is this gateway. */
#include <config.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#include "racoon.h"
#include "isakmp.h"
#include "ikev2.h"
#include "isakmp_impl.h"
#include "ikev2_impl.h"
#include "crypto_impl.h"
#include "ratelimit.h"
#include "debug.h"

#ifndef QCD_SECRET_PATH
#define QCD_SECRET_PATH	"/var/lib/racoon2/qcd.secret"
#endif

#define QCD_SECRET_LEN	32
#define QCD_TOKEN_LEN	16

static rc_vchar_t *qcd_secret;

static int
qcd_load_secret(void)
{
	int fd;
	uint8_t buf[QCD_SECRET_LEN];
	ssize_t n;

	fd = open(QCD_SECRET_PATH, O_RDONLY);
	if (fd < 0)
		return -1;
	n = read(fd, buf, QCD_SECRET_LEN);
	close(fd);
	if (n != QCD_SECRET_LEN)
		return -1;
	if (qcd_secret)
		rc_vfreez(qcd_secret);
	qcd_secret = rc_vnew(buf, QCD_SECRET_LEN);
	return qcd_secret ? 0 : -1;
}

static int
qcd_save_secret(void)
{
	int fd;
	ssize_t n;

	if (!qcd_secret || qcd_secret->l != QCD_SECRET_LEN)
		return -1;
	(void)mkdir("/var/lib/racoon2", 0700);
	fd = open(QCD_SECRET_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0)
		return -1;
	n = write(fd, qcd_secret->v, QCD_SECRET_LEN);
	close(fd);
	return n == QCD_SECRET_LEN ? 0 : -1;
}

int
ikev2_qcd_init(void)
{
	if (qcd_load_secret() == 0)
		return 0;
	qcd_secret = random_bytes(QCD_SECRET_LEN);
	if (!qcd_secret)
		return -1;
	if (qcd_save_secret() != 0) {
		plog(PLOG_INTWARN, PLOGLOC, 0,
		     "QCD secret not persisted at %s: %s\n",
		     QCD_SECRET_PATH, strerror(errno));
	}
	return 0;
}

rc_vchar_t *
ikev2_qcd_token(isakmp_cookie_t *i_ck, isakmp_cookie_t *r_ck)
{
	rc_vchar_t *in, *mac, *tok;
	uint8_t *p;

	if (!qcd_secret || !i_ck || !r_ck)
		return 0;
	in = rc_vmalloc(2 * sizeof(isakmp_cookie_t));
	if (!in)
		return 0;
	p = (uint8_t *)in->v;
	memcpy(p, i_ck, sizeof(isakmp_cookie_t));
	memcpy(p + sizeof(isakmp_cookie_t), r_ck, sizeof(isakmp_cookie_t));
	mac = hmacsha1_one(qcd_secret, in);
	rc_vfree(in);
	if (!mac)
		return 0;
	tok = rc_vnew(mac->v, QCD_TOKEN_LEN < mac->l ? QCD_TOKEN_LEN : mac->l);
	rc_vfree(mac);
	return tok;
}

void
ikev2_qcd_respond(rc_vchar_t *request, struct sockaddr *remote,
    struct sockaddr *local)
{
	struct ikev2_header *reqhdr;
	rc_vchar_t *tok = 0, *reply = 0;
	struct ikev2_header *replyhdr;
	struct ikev2payl_notify *n1, *n2;
	int n1_len, n2_len, reply_len;
	static struct ratelimit r;

	if (!request || !remote || !local)
		return;
	reqhdr = (struct ikev2_header *)request->v;
	if (!ratelimit(&r, remote))
		return;
	tok = ikev2_qcd_token(&reqhdr->initiator_spi, &reqhdr->responder_spi);
	if (!tok)
		return;

	n1_len = sizeof(struct ikev2payl_notify);
	n2_len = sizeof(struct ikev2payl_notify) + (int)tok->l;
	reply_len = sizeof(struct ikev2_header) + n1_len + n2_len;
	reply = rc_vmalloc(reply_len);
	if (!reply)
		goto end;

	replyhdr = (struct ikev2_header *)reply->v;
	memcpy(&replyhdr->initiator_spi, &reqhdr->initiator_spi,
	       sizeof(isakmp_cookie_t));
	memcpy(&replyhdr->responder_spi, &reqhdr->responder_spi,
	       sizeof(isakmp_cookie_t));
	replyhdr->next_payload = IKEV2_PAYLOAD_NOTIFY;
	replyhdr->version = IKEV2_VERSION;
	replyhdr->exchange_type = IKEV2EXCH_INFORMATIONAL;
	replyhdr->flags = IKEV2FLAG_RESPONSE;
	replyhdr->message_id = reqhdr->message_id;
	replyhdr->length = htonl(reply_len);

	n1 = (struct ikev2payl_notify *)(replyhdr + 1);
	set_payload_header(&n1->header, IKEV2_PAYLOAD_NOTIFY, n1_len);
	n1->nh.protocol_id = 0;
	n1->nh.spi_size = 0;
	put_uint16(&n1->nh.notify_message_type, IKEV2_INVALID_IKE_SPI);

	n2 = (struct ikev2payl_notify *)((uint8_t *)n1 + n1_len);
	set_payload_header(&n2->header, IKEV2_NO_NEXT_PAYLOAD, n2_len);
	/* RFC 6290 §4.1: QCD_TOKEN is tied to the IKE SA, Protocol ID 1 */
	n2->nh.protocol_id = 1;
	n2->nh.spi_size = 0;
	put_uint16(&n2->nh.notify_message_type, IKEV2_QCD_TOKEN);
	memcpy(n2 + 1, tok->v, tok->l);

	isakmp_log(0, local, remote, request, PLOG_INFO, PLOGLOC,
		   "QCD_TOKEN: unknown IKE_SA, sending unprotected token\n");
	isakmp_sendto(reply, remote, local);

      end:
	if (tok)
		rc_vfree(tok);
	if (reply)
		rc_vfree(reply);
}

int
ikev2_qcd_taker_recv(struct ikev2_sa *ike_sa, rc_vchar_t *packet)
{
	struct ikev2_header *ikehdr;
	struct ikev2_payload_header *p;
	int type;

	if (!ike_sa || !packet || !ike_sa->qcd_token_peer)
		return 0;
	ikehdr = (struct ikev2_header *)packet->v;
	p = (struct ikev2_payload_header *)(ikehdr + 1);
	for (type = ikehdr->next_payload;
	     type != IKEV2_NO_NEXT_PAYLOAD;
	     POINT_NEXT_PAYLOAD(p, type)) {
		struct ikev2payl_notify *n;
		size_t tot, hdr, dlen;
		uint8_t *data;

		if (type != IKEV2_PAYLOAD_NOTIFY)
			continue;
		n = (struct ikev2payl_notify *)p;
		if (get_notify_type(n) != IKEV2_QCD_TOKEN)
			continue;
		tot = get_payload_length(&n->header);
		hdr = sizeof(*n) + n->nh.spi_size;
		if (tot < hdr)
			continue;
		dlen = tot - hdr;
		data = get_notify_data(n);
		if (ike_sa->qcd_token_peer->l == dlen &&
		    memcmp(ike_sa->qcd_token_peer->v, data, dlen) == 0) {
			isakmp_log(ike_sa, 0, 0, 0, PLOG_INFO, PLOGLOC,
				   "QCD_TOKEN match, deleting IKE_SA\n");
			return 1;
		}
	}
	return 0;
}
