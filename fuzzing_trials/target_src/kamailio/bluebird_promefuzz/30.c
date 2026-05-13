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

int LLVMFuzzerTestOneInput_30(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    struct hdr_field *hf = create_hdr_field(Data, Size, HDR_OTHER_T);
    if (!hf) {
        return 0;
    }

    if (hf->body.s && hf->body.len > 0) {

        // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function parse_sipifmatch with parse_subscription_state
        parse_subscription_state(hf);
        // End mutation: Producer.REPLACE_FUNC_MUTATOR



        // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function parse_rr with parse_sipifmatch
        parse_sipifmatch(hf);
        // End mutation: Producer.REPLACE_FUNC_MUTATOR



        // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from parse_rr to parse_hname2_short
        const sip_msg_t zszjlwjd;
        memset(&zszjlwjd, 0, sizeof(zszjlwjd));
        char* ret_get_body_sucis = get_body(&zszjlwjd);
        if (ret_get_body_sucis == NULL){
        	return 0;
        }
        const sip_msg_t epcutxvb;
        memset(&epcutxvb, 0, sizeof(epcutxvb));
        char* ret_get_body_cvjna = get_body(&epcutxvb);
        if (ret_get_body_cvjna == NULL){
        	return 0;
        }

        char* ret_parse_hname2_short_glumv = parse_hname2_short(ret_get_body_sucis, ret_get_body_cvjna, hf);
        if (ret_parse_hname2_short_glumv == NULL){
        	return 0;
        }

        // End mutation: Producer.APPEND_MUTATOR

        parse_event(hf);
        parse_allow_header(hf);
    }

    fuzz_event_parser(Data, Size);

    free_hdr_field(hf);
    return 0;
}