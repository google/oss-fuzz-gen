// This fuzz driver is generated for library kamailio, aiming to fuzz the following functions:
// parse_sip_header_name at parse_hname2.c:239:7 in parse_hname2.h
// parse_supported at parse_supported.c:35:5 in parse_supported.h
// parse_method_name at parse_methods.c:55:5 in parse_methods.h
// set_instance at msg_parser.c:926:5 in msg_parser.h
// parse_identityinfo at parse_identityinfo.c:40:6 in parse_identityinfo.h
// parse_allow at parse_allow.c:86:5 in parse_allow.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "parse_supported.h"
#include "parse_allow.h"
#include "parse_hname2.h"
#include "parse_methods.h"
#include "parse_identityinfo.h"
#include "msg_parser.h"

static void fuzz_parse_sip_header_name(const uint8_t *Data, size_t Size) {
    if (Size < 2) return;

    char *begin = (char *)Data;
    const char *end = (char *)(Data + Size - 1);
    hdr_field_t hdr;
    int emode = 0;
    int logmode = 0;

    parse_sip_header_name(begin, end, &hdr, emode, logmode);
}

static void fuzz_parse_supported(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(struct sip_msg)) return;

    struct sip_msg msg;
    memset(&msg, 0, sizeof(struct sip_msg));
    msg.buf = (char *)Data;
    msg.len = Size;

    parse_supported(&msg);
}

static void fuzz_parse_method_name(const uint8_t *Data, size_t Size) {
    if (Size < 1) return;

    str s;
    s.s = (char *)Data;
    s.len = Size;

    enum request_method method;
    parse_method_name(&s, &method);
}

static void fuzz_set_instance(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(struct sip_msg)) return;

    struct sip_msg msg;
    memset(&msg, 0, sizeof(struct sip_msg));

    str instance;
    instance.s = (char *)Data;
    instance.len = Size;

    set_instance(&msg, &instance);
}

static void fuzz_parse_identityinfo(const uint8_t *Data, size_t Size) {
    if (Size < 2) return;

    char *buffer = (char *)Data;
    char *end = (char *)(Data + Size - 1);
    struct identityinfo_body ii_b;

    parse_identityinfo(buffer, end, &ii_b);
}

static void fuzz_parse_allow(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(struct sip_msg)) return;

    struct sip_msg msg;
    memset(&msg, 0, sizeof(struct sip_msg));
    msg.buf = (char *)Data;
    msg.len = Size;

    parse_allow(&msg);
}

int LLVMFuzzerTestOneInput_109(const uint8_t *Data, size_t Size) {
    fuzz_parse_sip_header_name(Data, Size);
    fuzz_parse_supported(Data, Size);
    fuzz_parse_method_name(Data, Size);
    fuzz_set_instance(Data, Size);
    fuzz_parse_identityinfo(Data, Size);
    fuzz_parse_allow(Data, Size);

    return 0;
}