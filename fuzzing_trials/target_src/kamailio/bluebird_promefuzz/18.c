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
#include "/src/kamailio/src/core/parser/parse_hname2.h"
#include "/src/kamailio/src/core/parser/parse_methods.h"
#include "/src/kamailio/src/core/parser/parse_identityinfo.h"
#include "/src/kamailio/src/core/parser/msg_parser.h"

static void fuzz_parse_sip_header_name(const uint8_t *Data, size_t Size) {
    if (Size < 2) {
        return;
    }

    char *begin = (char *)Data;
    const char *end = (char *)(Data + Size - 1);
    hdr_field_t hdr;
    int emode = 0;
    int logmode = 0;

    parse_sip_header_name(begin, end, &hdr, emode, logmode);
}

static void fuzz_parse_supported(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(struct sip_msg)) {
        return;
    }

    struct sip_msg msg;
    memset(&msg, 0, sizeof(struct sip_msg));
    msg.buf = (char *)Data;
    msg.len = Size;

    parse_supported(&msg);
}

static void fuzz_parse_method_name(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return;
    }

    str s;
    s.s = (char *)Data;
    s.len = Size;

    enum request_method method;
    parse_method_name(&s, &method);
}

static void fuzz_set_instance(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(struct sip_msg)) {
        return;
    }

    struct sip_msg msg;
    memset(&msg, 0, sizeof(struct sip_msg));

    str instance;
    instance.s = (char *)Data;
    instance.len = Size;

    set_instance(&msg, &instance);
}

static void fuzz_parse_identityinfo(const uint8_t *Data, size_t Size) {
    if (Size < 2) {
        return;
    }

    char *buffer = (char *)Data;
    char *end = (char *)(Data + Size - 1);
    struct identityinfo_body ii_b;

    parse_identityinfo(buffer, end, &ii_b);
}

static void fuzz_parse_allow(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(struct sip_msg)) {
        return;
    }

    struct sip_msg msg;
    memset(&msg, 0, sizeof(struct sip_msg));
    msg.buf = (char *)Data;
    msg.len = Size;


    // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function parse_allow with parse_from_header
    parse_from_header(&msg);
    // End mutation: Producer.REPLACE_FUNC_MUTATOR


}

int LLVMFuzzerTestOneInput_18(const uint8_t *Data, size_t Size) {
    fuzz_parse_sip_header_name(Data, Size);
    fuzz_parse_supported(Data, Size);
    fuzz_parse_method_name(Data, Size);
    fuzz_set_instance(Data, Size);
    fuzz_parse_identityinfo(Data, Size);
    fuzz_parse_allow(Data, Size);

    return 0;
}