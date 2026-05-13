#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "/src/kamailio/src/core/parser/parse_rr.h"
#include "/src/kamailio/src/core/parser/parse_event.h"
#include "/src/kamailio/src/core/parser/parse_sipifmatch.h"
#include "/src/kamailio/src/core/parser/parse_allow.h"

static struct hdr_field *create_hdr_field(const uint8_t *Data, size_t Size, hdr_types_t type) {
    struct hdr_field *hf = malloc(sizeof(struct hdr_field));
    if (!hf) {
        return NULL;
    }

    hf->type = type;
    hf->name.s = NULL;
    hf->name.len = 0;
    hf->body.s = malloc(Size + 1);
    if (!hf->body.s) {
        free(hf);
        return NULL;
    }
    memcpy(hf->body.s, Data, Size);
    hf->body.s[Size] = '\0';
    hf->body.len = Size;
    hf->len = Size;
    hf->parsed = NULL;
    hf->next = NULL;
    
    return hf;
}

static void free_hdr_field(struct hdr_field *hf) {
    if (hf) {
        free(hf->body.s);
        free(hf);
    }
}

static void fuzz_event_parser(const uint8_t *Data, size_t Size) {
    if (Size > 0) {
        event_t e;
        e.name.s = (char *)Data;
        e.name.len = Size;
        e.type = EVENT_OTHER;
        memset(&e.params.hooks, 0, sizeof(e.params.hooks));
        e.params.list = NULL;
        event_parser((char *)Data, Size, &e);
        print_event(&e);
    }
}

int LLVMFuzzerTestOneInput_66(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    struct hdr_field *hf = create_hdr_field(Data, Size, HDR_OTHER_T);
    if (!hf) {
        return 0;
    }

    if (hf->body.s && hf->body.len > 0) {

        // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function parse_sipifmatch with parse_event
        parse_event(hf);
        // End mutation: Producer.REPLACE_FUNC_MUTATOR


        parse_rr(hf);
        parse_event(hf);
        parse_allow_header(hf);
    }

    fuzz_event_parser(Data, Size);

    free_hdr_field(hf);
    return 0;
}