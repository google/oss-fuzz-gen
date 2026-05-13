#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "/src/kamailio/src/core/parser/parse_privacy.h"
#include "/src/kamailio/src/core/parser/msg_parser.h"

static void initialize_sip_msg(sip_msg_t *msg) {
    memset(msg, 0, sizeof(sip_msg_t));
    msg->instance.s = NULL;
    msg->new_uri.s = NULL;
    msg->privacy = malloc(sizeof(struct hdr_field));
    if (msg->privacy) {
        memset(msg->privacy, 0, sizeof(struct hdr_field));
    }
}

static void cleanup_sip_msg(sip_msg_t *msg) {
    if (msg->privacy) {
        free(msg->privacy);
    }
}

int LLVMFuzzerTestOneInput_29(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(sip_msg_t)) {
        return 0;
    }

    sip_msg_t msg;
    initialize_sip_msg(&msg);

    // Fuzz reset_instance
    reset_instance(&msg);

    // Fuzz msg_ldata_reset
    msg_ldata_reset(&msg);

    // Fuzz reset_ua
    reset_ua(&msg);

    // Fuzz reset_new_uri
    reset_new_uri(&msg);

    // Fuzz parse_privacy
    int parse_result = parse_privacy(&msg);
    if (parse_result == -1) {
        // Handle parse error if needed
    }

    // Fuzz free_sip_msg
    free_sip_msg(&msg);

    cleanup_sip_msg(&msg);
    return 0;
}