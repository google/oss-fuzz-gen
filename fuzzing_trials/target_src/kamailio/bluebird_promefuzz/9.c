#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "/src/kamailio/src/core/parser/parse_content.h"
#include "/src/kamailio/src/core/parser/parse_retry_after.h"
#include "/src/kamailio/src/core/parser/parser_f.h"
#include "/src/kamailio/src/core/parser/parse_hname2.h"

static void fuzz_parse_hname2(const uint8_t *Data, size_t Size) {
    if (Size < 2) {
        return;
    }

    struct hdr_field hdr;
    hdr.name.s = NULL;
    hdr.body.s = NULL;
    hdr.parsed = NULL;
    hdr.next = NULL;

    char *begin = (char *)Data;
    const char *end = (char *)(Data + Size);
    

    // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function parse_hname2 with parse_to_body
    parse_to_body(begin, end, &hdr);
    // End mutation: Producer.REPLACE_FUNC_MUTATOR


}

static void fuzz_eat_space_end(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return;
    }

    const char *p = (const char *)Data;
    const char *pend = (const char *)(Data + Size);

    eat_space_end(p, pend);
}

static void fuzz_eat_lws_end(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return;
    }

    const char *p = (const char *)Data;
    const char *pend = (const char *)(Data + Size);

    eat_lws_end(p, pend);
}

static void fuzz_parse_retry_after(const uint8_t *Data, size_t Size) {
    if (Size < 2) {
        return;
    }

    char *buf = (char *)Data;
    const char *end = (const char *)(Data + Size);
    unsigned after;
    int err;

    parse_retry_after(buf, end, &after, &err);
}

static void fuzz_eat_token_end(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return;
    }

    const char *p = (const char *)Data;
    const char *pend = (const char *)(Data + Size);

    eat_token_end(p, pend);
}

static void fuzz_decode_mime_type(const uint8_t *Data, size_t Size) {
    if (Size < 2) {
        return;
    }

    char *start = (char *)Data;
    const char *end = (const char *)(Data + Size - 1); // Ensure end points within bounds
    unsigned int mime_type;


    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 2 of decode_mime_type
    const unsigned int yruwxfdq = 1;
    decode_mime_type(start, end, &yruwxfdq);
    // End mutation: Producer.REPLACE_ARG_MUTATOR


}

int LLVMFuzzerTestOneInput_9(const uint8_t *Data, size_t Size) {
    fuzz_parse_hname2(Data, Size);
    fuzz_eat_space_end(Data, Size);
    fuzz_eat_lws_end(Data, Size);
    fuzz_parse_retry_after(Data, Size);
    fuzz_eat_token_end(Data, Size);
    fuzz_decode_mime_type(Data, Size);
    return 0;
}