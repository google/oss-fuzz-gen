#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "/src/kamailio/src/core/parser/parse_hname2.h"
#include "/src/kamailio/src/core/parser/hf.h"
#include "/src/kamailio/src/core/parser/parse_identity.h"
#include "/src/kamailio/src/core/parser/msg_parser.h"

static void fuzz_parse_hname2(const uint8_t *Data, size_t Size) {
    if (Size < 2) {
        return;
    } // Ensure there's enough data
    struct hdr_field hdr = {0};
    char *begin = (char *)Data;
    char *end = begin + Size;

    // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function parse_hname2 with parse_to_body
    parse_to_body(begin, end, &hdr);
    // End mutation: Producer.REPLACE_FUNC_MUTATOR


    clean_hdr_field(&hdr);
}

static void fuzz_get_hdr_field(const uint8_t *Data, size_t Size) {
    if (Size < 2) {
        return;
    } // Ensure there's enough data
    struct hdr_field hdr = {0};
    char *buf = (char *)Data;
    char *end = buf + Size;
    get_hdr_field(buf, end, &hdr);
    clean_hdr_field(&hdr);
}

static void fuzz_parse_hname2_short(const uint8_t *Data, size_t Size) {
    if (Size < 2) {
        return;
    } // Ensure there's enough data
    struct hdr_field hdr = {0};
    char *begin = (char *)Data;
    char *end = begin + Size;
    parse_hname2_short(begin, end, &hdr);
    clean_hdr_field(&hdr);
}

static void fuzz_parse_identity(const uint8_t *Data, size_t Size) {
    if (Size < 2) {
        return;
    } // Ensure there's enough data
    struct identity_body ib = {0};
    char *buf = (char *)Data;
    char *end = buf + Size;

    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 1 of parse_identity
    parse_identity(buf, NULL, &ib);
    // End mutation: Producer.REPLACE_ARG_MUTATOR


    if (ib.ballocated) {
        free(ib.hash.s);
    }
}

int LLVMFuzzerTestOneInput_77(const uint8_t *Data, size_t Size) {
    // Invoke each fuzz target function
    fuzz_parse_hname2(Data, Size);
    fuzz_get_hdr_field(Data, Size);
    fuzz_parse_hname2_short(Data, Size);
    fuzz_parse_identity(Data, Size);

    return 0;
}