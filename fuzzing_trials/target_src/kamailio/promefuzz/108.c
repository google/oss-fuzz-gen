// This fuzz driver is generated for library kamailio, aiming to fuzz the following functions:
// get_rcv_socket_uri at msg_parser.c:1331:5 in msg_parser.h
// uri_type_to_str at parse_uri.c:1495:6 in parse_uri.h
// get_src_address_socket at msg_parser.c:1269:5 in msg_parser.h
// get_src_uri at msg_parser.c:1186:5 in msg_parser.h
// proto_type_to_str at parse_uri.c:1524:6 in parse_uri.h
// parse_privacy at parse_privacy.c:155:5 in parse_privacy.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "parse_uri.h"
#include "parse_privacy.h"
#include "msg_parser.h"

static void initialize_sip_msg(sip_msg_t *msg) {
    memset(msg, 0, sizeof(sip_msg_t));
    msg->rcv.src_ip.af = AF_INET;
    msg->rcv.src_ip.len = 4;
    msg->rcv.dst_ip.af = AF_INET;
    msg->rcv.dst_ip.len = 4;
    msg->rcv.src_port = 5060;
    msg->rcv.dst_port = 5060;
}

static void initialize_str(str *s) {
    s->s = (char *)malloc(256);
    s->len = 256;
}

static void cleanup_str(str *s) {
    if (s->s) {
        free(s->s);
        s->s = NULL;
    }
}

int LLVMFuzzerTestOneInput_108(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(sip_msg_t)) {
        return 0;
    }

    sip_msg_t msg;
    str uri;
    int tmode = Data[0] % 2; // Random transport mode
    int atype = Data[1] % 2; // Random address type

    initialize_sip_msg(&msg);
    initialize_str(&uri);

    // Fuzz get_rcv_socket_uri
    int result = get_rcv_socket_uri(&msg, tmode, &uri, atype);
    if (result == -1) {
        // Handle error if needed
    }

    // Fuzz uri_type_to_str
    uri_type type = (uri_type)(Data[2] % 6); // Random uri_type
    uri_type_to_str(type, &uri);

    // Fuzz get_src_address_socket
    result = get_src_address_socket(&msg, &uri);
    if (result == -1) {
        // Handle error if needed
    }

    // Fuzz get_src_uri
    result = get_src_uri(&msg, tmode, &uri);
    if (result == -1) {
        // Handle error if needed
    }

    // Fuzz proto_type_to_str
    unsigned short proto_type = (unsigned short)(Data[3] % 65536); // Random proto type
    proto_type_to_str(proto_type, &uri);

    // Fuzz parse_privacy
    result = parse_privacy(&msg);
    if (result == -1) {
        // Handle error if needed
    }

    cleanup_str(&uri);

    return 0;
}