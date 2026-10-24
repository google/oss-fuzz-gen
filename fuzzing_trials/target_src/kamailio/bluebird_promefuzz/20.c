#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "/src/kamailio/src/core/parser/parse_supported.h"
#include "/src/kamailio/src/core/parser/parse_allow.h"
#include "/src/kamailio/src/core/parser/parse_via.h"
#include "/src/kamailio/src/core/parser/parse_uri.h"
#include "/src/kamailio/src/core/parser/parse_ppi_pai.h"
#include "/src/kamailio/src/core/parser/msg_parser.h"

static void initialize_sip_msg(struct sip_msg *msg) {
    memset(msg, 0, sizeof(struct sip_msg));
    msg->buf = (char *)malloc(1024);
    msg->len = 1024;
    msg->headers = NULL;
    msg->body = NULL;
}

static void cleanup_sip_msg(struct sip_msg *msg) {
    if (msg->buf) {
        free(msg->buf);
    }
    struct hdr_field *header = msg->headers;
    while (header) {
        struct hdr_field *next = header->next;
        free(header);
        header = next;
    }
}

int LLVMFuzzerTestOneInput_20(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(struct sip_msg)) {
        return 0;
    }

    struct sip_msg msg;
    initialize_sip_msg(&msg);

    memcpy(msg.buf, Data, Size < msg.len ? Size : msg.len);

    // Fuzz parse_supported
    int result_supported = parse_supported(&msg);
    if (result_supported == 0) {
        // Successfully parsed, explore further if needed
    }

    // Fuzz parse_via_header
    struct via_body *via_out = NULL;
    int result_via = parse_via_header(&msg, 1, &via_out);
    if (result_via == 0 && via_out != NULL) {
        // Successfully parsed, explore further if needed
    }

    // Fuzz parse_ppi_header
    int result_ppi = parse_ppi_header(&msg);
    if (result_ppi == 0) {
        // Successfully parsed, explore further if needed
    }

    // Fuzz check_transaction_quadruple
    int result_quadruple = check_transaction_quadruple(&msg);
    if (result_quadruple == 1) {
        // Successfully checked, explore further if needed
    }

    // Fuzz parse_allow
    int result_allow = parse_allow(&msg);
    if (result_allow == 0) {
        // Successfully parsed, explore further if needed
    }

    // Fuzz parse_orig_ruri
    int result_ruri = parse_orig_ruri(&msg);
    if (result_ruri >= 0) {
        // Successfully parsed, explore further if needed
    }

    cleanup_sip_msg(&msg);
    return 0;
}