#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "/src/kamailio/src/core/parser/parse_content.h"
#include "/src/kamailio/src/core/parser/parse_privacy.h"
#include "/src/kamailio/src/core/parser/parse_identityinfo.h"
#include "/src/kamailio/src/core/parser/parse_identity.h"
#include "/src/kamailio/src/core/parser/parse_ppi_pai.h"
#include "/src/kamailio/src/core/parser/msg_parser.h"

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

    // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function parse_accept_hdr with parse_content_type_hdr
    return parse_content_type_hdr(msg);
    // End mutation: Producer.REPLACE_FUNC_MUTATOR


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

int LLVMFuzzerTestOneInput_43(const uint8_t *Data, size_t Size) {
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