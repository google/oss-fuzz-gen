// This fuzz driver is generated for library kamailio, aiming to fuzz the following functions:
// free_sip_msg at msg_parser.c:802:6 in msg_parser.h
// parse_identityinfo_header at parse_identityinfo.c:325:5 in parse_identityinfo.h
// parse_record_route_headers at parse_rr.c:515:5 in parse_rr.h
// parse_route_headers at parse_rr.c:538:5 in parse_rr.h
// get_src_uri at msg_parser.c:1186:5 in msg_parser.h
// get_src_address_socket at msg_parser.c:1269:5 in msg_parser.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "parse_rr.h"
#include "parse_identityinfo.h"
#include "msg_parser.h"

static void initialize_sip_msg(sip_msg_t *msg) {
    memset(msg, 0, sizeof(sip_msg_t));
    msg->identity_info = NULL;
    msg->headers = NULL;
    msg->rcv.bind_address = NULL;
}

static void initialize_str(str *s) {
    s->s = NULL;
    s->len = 0;
}

static void cleanup_sip_msg(sip_msg_t *msg) {
    free_sip_msg(msg);
}

int LLVMFuzzerTestOneInput_2(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(sip_msg_t)) {
        return 0;
    }

    sip_msg_t msg;
    initialize_sip_msg(&msg);

    // Copy data into the sip_msg buffer
    msg.buf = (char *)malloc(Size);
    if (!msg.buf) {
        return 0;
    }
    memcpy(msg.buf, Data, Size);
    msg.len = Size;

    // Initialize additional structures
    str ssock;
    initialize_str(&ssock);

    str uri;
    initialize_str(&uri);

    int tmode = 0; // Example transport mode

    // Begin fuzzing the target functions
    parse_identityinfo_header(&msg);
    parse_record_route_headers(&msg);
    parse_route_headers(&msg);
    get_src_uri(&msg, tmode, &uri);
    get_src_address_socket(&msg, &ssock);

    // Clean up
    free(msg.buf);
    cleanup_sip_msg(&msg);

    return 0;
}