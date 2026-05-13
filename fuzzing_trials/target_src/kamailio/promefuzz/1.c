// This fuzz driver is generated for library kamailio, aiming to fuzz the following functions:
// reset_ruid at msg_parser.c:996:6 in msg_parser.h
// reset_instance at msg_parser.c:956:6 in msg_parser.h
// reset_path_vector at msg_parser.c:913:6 in msg_parser.h
// reset_new_uri at msg_parser.c:827:6 in msg_parser.h
// reset_ua at msg_parser.c:1037:6 in msg_parser.h
// reset_dst_uri at msg_parser.c:873:6 in msg_parser.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "msg_parser.h"

static void initialize_sip_msg(struct sip_msg *msg) {
    memset(msg, 0, sizeof(struct sip_msg));
    // Initialize required fields with dummy data
    msg->new_uri.s = strdup("sip:user@example.com");
    msg->new_uri.len = strlen(msg->new_uri.s);

    msg->dst_uri.s = strdup("sip:destination@example.com");
    msg->dst_uri.len = strlen(msg->dst_uri.s);

    msg->ruid.s = strdup("ruid-string");
    msg->ruid.len = strlen(msg->ruid.s);

    msg->instance.s = strdup("instance-string");
    msg->instance.len = strlen(msg->instance.s);

    msg->path_vec.s = strdup("path-vector-string");
    msg->path_vec.len = strlen(msg->path_vec.s);

    msg->location_ua.s = strdup("user-agent-string");
    msg->location_ua.len = strlen(msg->location_ua.s);
}

static void cleanup_sip_msg(struct sip_msg *msg) {
    free(msg->new_uri.s);
    free(msg->dst_uri.s);
    free(msg->ruid.s);
    free(msg->instance.s);
    free(msg->path_vec.s);
    free(msg->location_ua.s);
}

int LLVMFuzzerTestOneInput_1(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(struct sip_msg)) {
        return 0;
    }

    struct sip_msg msg;
    initialize_sip_msg(&msg);

    // Randomly choose a function to fuzz based on input data
    switch (Data[0] % 6) {
        case 0:
            reset_ruid(&msg);
            break;
        case 1:
            reset_instance(&msg);
            break;
        case 2:
            reset_path_vector(&msg);
            break;
        case 3:
            reset_new_uri(&msg);
            break;
        case 4:
            reset_ua(&msg);
            break;
        case 5:
            reset_dst_uri(&msg);
            break;
    }

    cleanup_sip_msg(&msg);
    return 0;
}