// This fuzz driver is generated for library kamailio, aiming to fuzz the following functions:
// parse_supported at parse_supported.c:35:5 in parse_supported.h
// free_date at parse_date.c:249:6 in parse_date.h
// parse_date_header at parse_date.c:215:5 in parse_date.h
// parse_msg at msg_parser.c:698:5 in msg_parser.h
// parse_subscription_state at parse_subscription_state.c:134:5 in parse_subscription_state.h
// parse_date at parse_date.c:197:6 in parse_date.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "parse_supported.h"
#include "parse_date.h"
#include "msg_parser.h"
#include "parse_subscription_state.h"

static void fuzz_parse_supported(struct sip_msg *msg) {
    parse_supported(msg);
}

static void fuzz_free_date(struct date_body *db) {
    free_date(db);
}

static void fuzz_parse_date_header(struct sip_msg *msg) {
    parse_date_header(msg);
}

static void fuzz_parse_msg(char *buf, unsigned int len, struct sip_msg *msg) {
    parse_msg(buf, len, msg);
}

static void fuzz_parse_subscription_state(struct hdr_field *h) {
    parse_subscription_state(h);
}

static void fuzz_parse_date(char *buf, char *end, struct date_body *db) {
    parse_date(buf, end, db);
}

int LLVMFuzzerTestOneInput_22(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(struct sip_msg)) return 0;

    struct sip_msg msg;
    memset(&msg, 0, sizeof(msg));

    struct date_body db;
    memset(&db, 0, sizeof(db));

    struct hdr_field header;
    memset(&header, 0, sizeof(header));

    char *buffer = (char *)Data;
    unsigned int len = (unsigned int)Size;

    // Fuzz parse_supported
    fuzz_parse_supported(&msg);

    // Fuzz free_date
    fuzz_free_date(&db);

    // Fuzz parse_date_header
    fuzz_parse_date_header(&msg);

    // Fuzz parse_msg
    fuzz_parse_msg(buffer, len, &msg);

    // Fuzz parse_subscription_state
    fuzz_parse_subscription_state(&header);

    // Fuzz parse_date
    fuzz_parse_date(buffer, buffer + len, &db);

    return 0;
}