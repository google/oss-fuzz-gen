// This fuzz driver is generated for library kamailio, aiming to fuzz the following functions:
// parse_msg at msg_parser.c:698:5 in msg_parser.h
// parse_headers at msg_parser.c:307:5 in msg_parser.h
// parse_from_header at parse_from.c:50:5 in parse_from.h
// parse_from_uri at parse_from.c:88:12 in parse_from.h
// parse_to_header at parse_to.c:73:5 in parse_addr_spec.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "parse_from.h"
#include "parse_addr_spec.h"
#include "msg_parser.h"

#define DUMMY_FILE "./dummy_file"

static void initialize_sip_msg(sip_msg_t *msg, char *buf, unsigned int len) {
    memset(msg, 0, sizeof(sip_msg_t));
    msg->buf = buf;
    msg->len = len;
}

int LLVMFuzzerTestOneInput_16(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    FILE *file = fopen(DUMMY_FILE, "wb");
    if (!file) return 0;
    fwrite(Data, 1, Size, file);
    fclose(file);

    char *buf = (char *)malloc(Size + 1);
    if (!buf) return 0;
    memcpy(buf, Data, Size);
    buf[Size] = '\0';

    sip_msg_t msg;
    initialize_sip_msg(&msg, buf, Size);

    if (parse_msg(buf, Size, &msg) == 0) {
        hdr_flags_t flags = 0; // Use appropriate flags as needed
        parse_headers(&msg, flags, 0);
        parse_from_header(&msg);
        parse_from_uri(&msg);
        parse_to_header(&msg);
    }

    free(buf);
    return 0;
}