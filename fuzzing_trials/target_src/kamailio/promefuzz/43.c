// This fuzz driver is generated for library kamailio, aiming to fuzz the following functions:
// parse_sipifmatch at parse_sipifmatch.c:77:5 in parse_sipifmatch.h
// clean_hdr_field at hf.c:56:6 in hf.h
// parse_rr at parse_rr.c:167:5 in parse_rr.h
// clean_hdr_field at hf.c:56:6 in hf.h
// parse_event at parse_event.c:148:5 in parse_event.h
// clean_hdr_field at hf.c:56:6 in hf.h
// parse_allow_header at parse_allow.c:45:5 in parse_allow.h
// clean_hdr_field at hf.c:56:6 in hf.h
// hdr_allocs_parse at hf.h:215:19 in hf.h
// clean_hdr_field at hf.c:56:6 in hf.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "parse_sipifmatch.h"
#include "parse_allow.h"
#include "parse_rr.h"
#include "parse_event.h"
#include "hf.h"

static void initialize_hdr_field(struct hdr_field *hf, const uint8_t *Data, size_t Size) {
    hf->type = HDR_OTHER_T;
    hf->name.s = Size > 0 ? (char *)Data : NULL;
    hf->name.len = Size > 0 ? (int)(Size / 2) : 0;
    hf->body.s = Size > hf->name.len ? (char *)(Data + hf->name.len) : NULL;
    hf->body.len = Size > hf->name.len ? (int)(Size - hf->name.len) : 0;
    hf->len = (int)Size;
    hf->parsed = NULL;
    hf->next = NULL;
}

int LLVMFuzzerTestOneInput_43(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    struct hdr_field hf;
    initialize_hdr_field(&hf, Data, Size);

    // Ensure that the body is not NULL and has a valid length before parsing
    if (hf.body.s && hf.body.len > 0) {
        if (hf.type == HDR_SIPIFMATCH_T) {
            parse_sipifmatch(&hf);
        }
        clean_hdr_field(&hf);
    }

    // Fuzz parse_rr
    initialize_hdr_field(&hf, Data, Size);
    if (hf.body.s && hf.body.len > 0) {
        if (hf.type == HDR_ROUTE_T || hf.type == HDR_RECORDROUTE_T) {
            parse_rr(&hf);
        }
        clean_hdr_field(&hf);
    }

    // Fuzz parse_event
    initialize_hdr_field(&hf, Data, Size);
    if (hf.body.s && hf.body.len > 0) {
        if (hf.type == HDR_EVENT_T) {
            parse_event(&hf);
        }
        clean_hdr_field(&hf);
    }

    // Fuzz parse_allow_header
    initialize_hdr_field(&hf, Data, Size);
    if (hf.body.s && hf.body.len > 0) {
        if (hf.type == HDR_ALLOW_T) {
            parse_allow_header(&hf);
        }
        clean_hdr_field(&hf);
    }

    // Fuzz hdr_allocs_parse
    initialize_hdr_field(&hf, Data, Size);
    if (hf.body.s && hf.body.len > 0) {
        hdr_allocs_parse(&hf);
        clean_hdr_field(&hf);
    }

    return 0;
}