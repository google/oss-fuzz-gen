#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "/src/kamailio/src/core/parser/parse_rr.h"
#include "/src/kamailio/src/core/parser/msg_parser.h"
#include "/src/kamailio/src/core/parser/parse_allow.h"

static sip_msg_t *initialize_sip_msg(const uint8_t *Data, size_t Size) {
    sip_msg_t *msg = (sip_msg_t *)malloc(sizeof(sip_msg_t));
    if (!msg) return NULL;

    memset(msg, 0, sizeof(sip_msg_t));
    msg->headers = (hdr_field_t *)malloc(sizeof(hdr_field_t));
    if (!msg->headers) {
        free(msg);
        return NULL;
    }

    msg->headers->name.s = (char *)malloc(Size);
    if (!msg->headers->name.s) {
        free(msg->headers);
        free(msg);
        return NULL;
    }
    memcpy(msg->headers->name.s, Data, Size);
    msg->headers->name.len = Size;
    msg->headers->body.s = (char *)malloc(Size);
    if (!msg->headers->body.s) {
        free(msg->headers->name.s);
        free(msg->headers);
        free(msg);
        return NULL;
    }
    memcpy(msg->headers->body.s, Data, Size);
    msg->headers->body.len = Size;

    msg->headers->next = NULL;
    return msg;
}

static void cleanup_sip_msg(sip_msg_t *msg) {
    if (msg) {
        if (msg->headers) {
            if (msg->headers->name.s) free(msg->headers->name.s);
            if (msg->headers->body.s) free(msg->headers->body.s);
            free(msg->headers);
        }
        free(msg);
    }
}

int LLVMFuzzerTestOneInput_17(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    sip_msg_t *msg = initialize_sip_msg(Data, Size);
    if (!msg) return 0;

    // Fuzz get_hdr_by_name
    get_hdr_by_name(msg, (const char *)Data, (int)Size);

    // Fuzz get_hdr
    if (Size >= sizeof(enum _hdr_types_t)) {
        enum _hdr_types_t ht;
        memcpy(&ht, Data, sizeof(enum _hdr_types_t));
        get_hdr(msg, ht);
    }

    // Fuzz parse_rr
    parse_rr(msg->headers);

    // Fuzz next_sibling_hdr
    next_sibling_hdr(msg->headers);

    // Fuzz parse_allow_header
    parse_allow_header(msg->headers);

    // Fuzz next_sibling_hdr_by_name
    next_sibling_hdr_by_name(msg->headers);

    cleanup_sip_msg(msg);
    return 0;
}