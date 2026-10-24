// This fuzz driver is generated for library kamailio, aiming to fuzz the following functions:
// parse_expires at parse_expires.c:104:5 in parse_expires.h
// parse_rr at parse_rr.c:167:5 in parse_rr.h
// parse_allow_header at parse_allow.c:45:5 in parse_allow.h
// hdr_allocs_parse at hf.h:215:19 in hf.h
// print_expires at parse_expires.c:144:6 in parse_expires.h
// free_expires at parse_expires.c:134:6 in parse_expires.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "parse_rr.h"
#include "hf.h"
#include "parse_expires.h"
#include "parse_allow.h"

static void initialize_hdr_field(struct hdr_field *hf, const uint8_t *data, size_t size) {
    hf->type = HDR_OTHER_T;
    hf->name.s = (char *)malloc(size + 1);
    if (hf->name.s) {
        memcpy(hf->name.s, data, size);
        hf->name.s[size] = '\0';
        hf->name.len = size;
    }
    hf->body.s = (char *)malloc(size + 1);
    if (hf->body.s) {
        memcpy(hf->body.s, data, size);
        hf->body.s[size] = '\0';
        hf->body.len = size;
    }
    hf->len = size;
    hf->parsed = NULL;
    hf->next = NULL;
}

static void cleanup_hdr_field(struct hdr_field *hf) {
    if (hf->name.s) {
        free(hf->name.s);
    }
    if (hf->body.s) {
        free(hf->body.s);
    }
}

int LLVMFuzzerTestOneInput_60(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    struct hdr_field hdr;
    initialize_hdr_field(&hdr, Data, Size);

    // Ensure that the body is not NULL before parsing
    if (hdr.body.s && hdr.body.len > 0) {
        if (hdr.type == HDR_EXPIRES_T) {
            parse_expires(&hdr);
        }
        if (hdr.type == HDR_ROUTE_T || hdr.type == HDR_RECORDROUTE_T) {
            parse_rr(&hdr);
        }
        if (hdr.type == HDR_ALLOW_T) {
            parse_allow_header(&hdr);
        }
    }

    int allocs = hdr_allocs_parse(&hdr);
    if (allocs) {
        exp_body_t *exp_body = (exp_body_t *)malloc(sizeof(exp_body_t));
        if (exp_body) {
            exp_body->text.s = hdr.body.s;
            exp_body->text.len = hdr.body.len;
            exp_body->valid = 1;
            exp_body->val = 0;

            print_expires(exp_body);
            free_expires(&exp_body);
        }
    }

    cleanup_hdr_field(&hdr);
    return 0;
}