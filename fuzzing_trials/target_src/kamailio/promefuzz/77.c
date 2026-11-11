// This fuzz driver is generated for library kamailio, aiming to fuzz the following functions:
// parse_accept_hdr at parse_content.c:534:5 in parse_content.h
// parse_identity_header at parse_identity.c:141:5 in parse_identity.h
// parse_identityinfo_header at parse_identityinfo.c:325:5 in parse_identityinfo.h
// parse_pai_header at parse_ppi_pai.c:132:5 in parse_ppi_pai.h
// parse_privacy at parse_privacy.c:155:5 in parse_privacy.h
// parse_msg at msg_parser.c:698:5 in msg_parser.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "parse_content.h"
#include "parse_privacy.h"
#include "parse_identityinfo.h"
#include "parse_identity.h"
#include "parse_ppi_pai.h"
#include "msg_parser.h"

static void init_sip_msg(struct sip_msg *msg) {
    memset(msg, 0, sizeof(struct sip_msg));
    msg->buf = malloc(1024); // Allocate a buffer for the SIP message
    msg->len = 1024;
}

static void cleanup_sip_msg(struct sip_msg *msg) {
    if (msg->buf) {
        free(msg->buf);
    }
}

static int fuzz_parse_accept_hdr(struct sip_msg *msg) {
    return parse_accept_hdr(msg);
}

static int fuzz_parse_identity_header(struct sip_msg *msg) {
    return parse_identity_header(msg);
}

static int fuzz_parse_identityinfo_header(struct sip_msg *msg) {
    return parse_identityinfo_header(msg);
}

static int fuzz_parse_pai_header(struct sip_msg *msg) {
    return parse_pai_header(msg);
}

static int fuzz_parse_privacy(struct sip_msg *msg) {
    return parse_privacy(msg);
}

static int fuzz_parse_msg(char *buf, unsigned int len, struct sip_msg *msg) {
    return parse_msg(buf, len, msg);
}

int LLVMFuzzerTestOneInput_77(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(struct sip_msg)) {
        return 0;
    }

    struct sip_msg msg;
    init_sip_msg(&msg);

    memcpy(msg.buf, Data, Size < msg.len ? Size : msg.len);

    fuzz_parse_accept_hdr(&msg);
    fuzz_parse_identity_header(&msg);
    fuzz_parse_identityinfo_header(&msg);
    fuzz_parse_pai_header(&msg);
    fuzz_parse_privacy(&msg);
    fuzz_parse_msg(msg.buf, msg.len, &msg);

    cleanup_sip_msg(&msg);
    return 0;
}