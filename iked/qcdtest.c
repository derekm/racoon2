/* Pre-authentication QCD walker regressions. No secret file is opened. */
#include "config.h"
#include <sys/types.h>
#include <sys/mman.h>
#include <unistd.h>
#include <getopt.h>
#include "racoon.h"
#include "plog.h"
#include "isakmp.h"
#include "isakmp_impl.h"
#include "ikev2.h"
#include "ikev2_impl.h"
#include "test_util.h"
TEST_MAIN_STUBS()

int main(int argc, char **argv)
{
    struct ikev2_sa sa;
    struct ikev2_header *h;
    struct ikev2_payload_header *p;
    struct ikev2payl_notify *n;
    rc_vchar_t packet;
    long pagesz = sysconf(_SC_PAGESIZE);
    unsigned char *mem;
    size_t len;
    (void)argc;
    test_init(argv[0]);
    memset(&sa, 0, sizeof(sa));
    sa.qcd_token_peer = rc_vmalloc(16);
    if (!sa.qcd_token_peer || pagesz <= 0) return 1;
    memset(sa.qcd_token_peer->v, 0x5a, 16);
    mem = mmap(NULL, (size_t)pagesz * 2, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANON, -1, 0);
    if (mem == MAP_FAILED || mprotect(mem + pagesz, (size_t)pagesz, PROT_NONE))
        return 1;
    /* ENCRYPTED's np names an inner payload, not another cleartext header.
     * The next byte is an inaccessible page even without sanitizers. */
    len = sizeof(*h) + sizeof(*p);
    packet.v = mem + pagesz - len; packet.l = len;
    memset(packet.v, 0, len);
    h = (struct ikev2_header *)packet.v;
    p = (struct ikev2_payload_header *)(h + 1);
    h->next_payload = IKEV2_PAYLOAD_ENCRYPTED;
    set_payload_header(p, IKEV2_PAYLOAD_NOTIFY, sizeof(*p));
    TEST_CHECK(ikev2_qcd_taker_recv(&sa, &packet) == 0);
    h->next_payload = IKEV2_PAYLOAD_ENCRYPTED_AND_AUTHENTICATED_FRAGMENT;
    TEST_CHECK(ikev2_qcd_taker_recv(&sa, &packet) == 0);
    /* A truncated Notify has a generic header but no notify type. */
    h->next_payload = IKEV2_PAYLOAD_NOTIFY;
    TEST_CHECK(ikev2_qcd_taker_recv(&sa, &packet) == 0);
    /* Bounds on generic payload length/advance. */
    h->next_payload = IKEV2_PAYLOAD_VENDOR_ID;
    put_uint16(&p->payload_length, 65535);
    TEST_CHECK(ikev2_qcd_taker_recv(&sa, &packet) == 0);
    put_uint16(&p->payload_length, 0);
    TEST_CHECK(ikev2_qcd_taker_recv(&sa, &packet) == 0);
    /* Positive control: a real unencrypted matching token is accepted. */
    len = sizeof(*h) + sizeof(*n) + 16;
    packet.v = mem + pagesz - len; packet.l = len;
    memset(packet.v, 0, len);
    h = (struct ikev2_header *)packet.v;
    h->next_payload = IKEV2_PAYLOAD_NOTIFY;
    n = (struct ikev2payl_notify *)(h + 1);
    set_payload_header(&n->header, IKEV2_NO_NEXT_PAYLOAD, sizeof(*n) + 16);
    put_uint16(&n->nh.notify_message_type, IKEV2_QCD_TOKEN);
    memcpy(n + 1, sa.qcd_token_peer->v, 16);
    TEST_CHECK(ikev2_qcd_taker_recv(&sa, &packet) == 1);
    ((unsigned char *)(n + 1))[15] ^= 1;
    TEST_CHECK(ikev2_qcd_taker_recv(&sa, &packet) == 0);
    /* Header itself truncated against the same guard page. */
    packet.v = mem + pagesz - 1; packet.l = 1;
    TEST_CHECK(ikev2_qcd_taker_recv(&sa, &packet) == 0);
    munmap(mem, (size_t)pagesz * 2);
    rc_vfree(sa.qcd_token_peer);
    return test_exit_status();
}
