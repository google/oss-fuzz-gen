// This fuzz driver is generated for library kamailio, aiming to fuzz the following functions:
// parse_rr at parse_rr.c:167:5 in parse_rr.h
// parse_event at parse_event.c:148:5 in parse_event.h
// parse_allow_header at parse_allow.c:45:5 in parse_allow.h
// parse_subscription_state at parse_subscription_state.c:134:5 in parse_subscription_state.h
// ksr_hname_init_config at parse_hname2.c:219:5 in parse_hname2.h
// ksr_hname_init_index at parse_hname2.c:186:5 in parse_hname2.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "parse_allow.h"
#include "parse_rr.h"
#include "parse_event.h"
#include "parse_hname2.h"
#include "parse_subscription_state.h"

static void initialize_hdr_field(struct hdr_field *hf, hdr_types_t type, const char *name, const char *body) {
    hf->type = type;
    hf->name.s = (char *)name;
    hf->name.len = strlen(name);
    hf->body.s = (char *)body;
    hf->body.len = strlen(body);
    hf->len = hf->name.len + hf->body.len + 1; // +1 for ':' separator
    hf->parsed = NULL;
    hf->next = NULL;
}

int LLVMFuzzerTestOneInput_119(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    struct hdr_field hf;
    char dummy_name[] = "Dummy-Header";
    char dummy_body[256];

    if (Size > sizeof(dummy_body) - 1) Size = sizeof(dummy_body) - 1;
    memcpy(dummy_body, Data, Size);
    dummy_body[Size] = '\0';

    // Initialize hdr_field for parsing functions
    initialize_hdr_field(&hf, HDR_OTHER_T, dummy_name, dummy_body);

    // Only call parse_rr if the type is appropriate
    if (hf.type == HDR_ROUTE_T || hf.type == HDR_RECORDROUTE_T) {
        parse_rr(&hf);
    }

    // Fuzz parse_event function
    if (hf.type == HDR_EVENT_T) {
        initialize_hdr_field(&hf, HDR_EVENT_T, dummy_name, dummy_body);
        parse_event(&hf);
    }

    // Fuzz parse_allow_header function
    if (hf.type == HDR_ALLOW_T) {
        initialize_hdr_field(&hf, HDR_ALLOW_T, dummy_name, dummy_body);
        parse_allow_header(&hf);
    }

    // Fuzz parse_subscription_state function
    if (hf.type == HDR_SUBSCRIPTION_STATE_T) {
        initialize_hdr_field(&hf, HDR_SUBSCRIPTION_STATE_T, dummy_name, dummy_body);
        parse_subscription_state(&hf);
    }

    // Fuzz ksr_hname_init_config function
    ksr_hname_init_config();

    // Fuzz ksr_hname_init_index function
    ksr_hname_init_index();

    return 0;
}