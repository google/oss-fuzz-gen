#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>
#include "/src/kamailio/src/core/parser/parse_uri.h"
#include "/src/kamailio/src/core/parser/msg_parser.h"
#include "/src/kamailio/src/core/parser/parse_addr_spec.h"
#include "/src/kamailio/src/core/parser/parse_content.h"

static void initialize_sip_msg(sip_msg_t *msg, const uint8_t *Data, size_t Size) {
    memset(msg, 0, sizeof(sip_msg_t));
    msg->buf = (char *)malloc(Size + 1);
    if (msg->buf) {
        memcpy(msg->buf, Data, Size);
        msg->buf[Size] = '\0';
        msg->len = Size;
    }
}

static void cleanup_sip_msg(sip_msg_t *msg) {
    if (msg->buf) {
        free(msg->buf);
        msg->buf = NULL;
    }
}

static void prepare_headers(sip_msg_t *msg) {
    // Initialize the 'to' header for parse_to_header
    msg->to = (struct hdr_field *)malloc(sizeof(struct hdr_field));
    if (msg->to) {
        msg->to->name.s = "To";
        msg->to->name.len = 2;
        msg->to->body.s = msg->buf; // Simplified: point to the start of the buffer
        msg->to->body.len = msg->len; // Simplified: assume entire buffer is the body
        msg->to->next = NULL;
    }

    // Initialize the 'content_type' header for parse_content_type_hdr
    msg->content_type = (struct hdr_field *)malloc(sizeof(struct hdr_field));
    if (msg->content_type) {
        msg->content_type->name.s = "Content-Type";
        msg->content_type->name.len = 12;
        msg->content_type->body.s = msg->buf; // Simplified: point to the start of the buffer
        msg->content_type->body.len = msg->len; // Simplified: assume entire buffer is the body
        msg->content_type->next = NULL;
    }
}

int LLVMFuzzerTestOneInput_16(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0; // Early exit if no data

    sip_msg_t msg;
    initialize_sip_msg(&msg, Data, Size);

    // Ensure msg.buf is valid before proceeding with parsing
    if (msg.buf && msg.len > 0) {
        prepare_headers(&msg);

        // Test parse_to_header
        parse_to_header(&msg);

        // Test parse_sip_msg_uri
        parse_sip_msg_uri(&msg);

        // Test parse_content_type_hdr
        parse_content_type_hdr(&msg);

        // Test msg_set_time
        msg_set_time(&msg);

        // Test parse_orig_ruri
        parse_orig_ruri(&msg);

        // Test parse_headers
        parse_headers(&msg, 0, 0);

        // Clean up allocated headers
        if (msg.to) {
            free(msg.to);
            msg.to = NULL;
        }
        if (msg.content_type) {
            free(msg.content_type);
            msg.content_type = NULL;
        }
    }

    cleanup_sip_msg(&msg);
    return 0;
}