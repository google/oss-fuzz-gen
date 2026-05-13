// This fuzz driver is generated for library kamailio, aiming to fuzz the following functions:
// parse_hname2 at parse_hname2.c:323:7 in parse_hname2.h
// clean_hdr_field at hf.c:56:6 in hf.h
// get_hdr_field at msg_parser.c:74:7 in msg_parser.h
// clean_hdr_field at hf.c:56:6 in hf.h
// parse_hname2_short at parse_hname2.c:333:7 in parse_hname2.h
// clean_hdr_field at hf.c:56:6 in hf.h
// parse_identity at parse_identity.c:78:6 in parse_identity.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "parse_hname2.h"
#include "hf.h"
#include "parse_identity.h"
#include "msg_parser.h"

static void fuzz_parse_hname2(const uint8_t *Data, size_t Size) {
    if (Size < 2) return; // Ensure there's enough data
    struct hdr_field hdr = {0};
    char *begin = (char *)Data;
    char *end = begin + Size;
    parse_hname2(begin, end, &hdr);
    clean_hdr_field(&hdr);
}

static void fuzz_get_hdr_field(const uint8_t *Data, size_t Size) {
    if (Size < 2) return; // Ensure there's enough data
    struct hdr_field hdr = {0};
    char *buf = (char *)Data;
    char *end = buf + Size;
    get_hdr_field(buf, end, &hdr);
    clean_hdr_field(&hdr);
}

static void fuzz_parse_hname2_short(const uint8_t *Data, size_t Size) {
    if (Size < 2) return; // Ensure there's enough data
    struct hdr_field hdr = {0};
    char *begin = (char *)Data;
    char *end = begin + Size;
    parse_hname2_short(begin, end, &hdr);
    clean_hdr_field(&hdr);
}

static void fuzz_parse_identity(const uint8_t *Data, size_t Size) {
    if (Size < 2) return; // Ensure there's enough data
    struct identity_body ib = {0};
    char *buf = (char *)Data;
    char *end = buf + Size;
    parse_identity(buf, end, &ib);
    if (ib.ballocated) {
        free(ib.hash.s);
    }
}

int LLVMFuzzerTestOneInput_42(const uint8_t *Data, size_t Size) {
    // Invoke each fuzz target function
    fuzz_parse_hname2(Data, Size);
    fuzz_get_hdr_field(Data, Size);
    fuzz_parse_hname2_short(Data, Size);
    fuzz_parse_identity(Data, Size);

    return 0;
}