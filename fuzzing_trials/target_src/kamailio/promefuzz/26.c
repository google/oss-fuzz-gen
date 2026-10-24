// This fuzz driver is generated for library kamailio, aiming to fuzz the following functions:
// parse_hname2 at parse_hname2.c:323:7 in parse_hname2.h
// eat_space_end at parser_f.h:43:21 in parser_f.h
// eat_lws_end at parser_f.h:50:21 in parser_f.h
// parse_retry_after at parse_retry_after.c:39:7 in parse_retry_after.h
// eat_token_end at parser_f.h:67:21 in parser_f.h
// decode_mime_type at parse_content.c:289:7 in parse_content.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "parse_content.h"
#include "parse_retry_after.h"
#include "parser_f.h"
#include "parse_hname2.h"

static void fuzz_parse_hname2(const uint8_t *Data, size_t Size) {
    if (Size < 2) return;

    struct hdr_field hdr;
    hdr.name.s = NULL;
    hdr.body.s = NULL;
    hdr.parsed = NULL;
    hdr.next = NULL;

    char *begin = (char *)Data;
    const char *end = (char *)(Data + Size);
    
    parse_hname2(begin, end, &hdr);
}

static void fuzz_eat_space_end(const uint8_t *Data, size_t Size) {
    if (Size < 1) return;

    const char *p = (const char *)Data;
    const char *pend = (const char *)(Data + Size);

    eat_space_end(p, pend);
}

static void fuzz_eat_lws_end(const uint8_t *Data, size_t Size) {
    if (Size < 1) return;

    const char *p = (const char *)Data;
    const char *pend = (const char *)(Data + Size);

    eat_lws_end(p, pend);
}

static void fuzz_parse_retry_after(const uint8_t *Data, size_t Size) {
    if (Size < 2) return;

    char *buf = (char *)Data;
    const char *end = (const char *)(Data + Size);
    unsigned after;
    int err;

    parse_retry_after(buf, end, &after, &err);
}

static void fuzz_eat_token_end(const uint8_t *Data, size_t Size) {
    if (Size < 1) return;

    const char *p = (const char *)Data;
    const char *pend = (const char *)(Data + Size);

    eat_token_end(p, pend);
}

static void fuzz_decode_mime_type(const uint8_t *Data, size_t Size) {
    if (Size < 2) return;

    char *start = (char *)Data;
    const char *end = (const char *)(Data + Size - 1); // Ensure end points within bounds
    unsigned int mime_type;

    decode_mime_type(start, end, &mime_type);
}

int LLVMFuzzerTestOneInput_26(const uint8_t *Data, size_t Size) {
    fuzz_parse_hname2(Data, Size);
    fuzz_eat_space_end(Data, Size);
    fuzz_eat_lws_end(Data, Size);
    fuzz_parse_retry_after(Data, Size);
    fuzz_eat_token_end(Data, Size);
    fuzz_decode_mime_type(Data, Size);
    return 0;
}