#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "/src/kamailio/src/core/parser/parse_sipifmatch.h"
#include "/src/kamailio/src/core/parser/msg_parser.h"
#include "/src/kamailio/src/core/parser/parse_via.h"

static void initialize_sip_msg(sip_msg_t *msg) {
    memset(msg, 0, sizeof(sip_msg_t));
    msg->id = rand();
    msg->pid = getpid();
}

static void initialize_via_body(via_body_t *via_body) {
    memset(via_body, 0, sizeof(via_body_t));
}

static void initialize_via_oc(via_oc_t *via_oc) {
    memset(via_oc, 0, sizeof(via_oc_t));
}

static void initialize_msg_ctx_id(msg_ctx_id_t *msg_ctx_id) {
    memset(msg_ctx_id, 0, sizeof(msg_ctx_id_t));
}

int LLVMFuzzerTestOneInput_68(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    sip_msg_t msg;
    initialize_sip_msg(&msg);

    via_body_t via_body;
    initialize_via_body(&via_body);

    via_oc_t via_oc;
    initialize_via_oc(&via_oc);

    msg_ctx_id_t msg_ctx_id;
    initialize_msg_ctx_id(&msg_ctx_id);

    // Attempt to parse a via header from the input data
    int header_index = Data[0] % 2 + 1; // Use 1 or 2 for the header index
    parse_via_header(&msg, header_index, &via_body);

    // Parse overload-control parameters from a Via header
    parse_via_oc(&msg, &via_body, &via_oc);

    // Parse the "Via" header from a buffer
    char buffer[256];
    size_t copy_size = Size < sizeof(buffer) ? Size : sizeof(buffer) - 1;
    memcpy(buffer, Data, copy_size);
    buffer[copy_size] = '\0';
    parse_via(buffer, buffer + copy_size, &via_body);

    // Free the via list if it's not empty
    if (via_body.bstart != NULL) {
        free_via_list(&via_body);
    }

    // Free SIP interface match
    str *sipifmatch = NULL;
    free_sipifmatch(&sipifmatch);

    // Set message context ID

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from free_sipifmatch to set_path_vector

    // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function parse_content_disposition with parse_privacy
    int ret_parse_content_disposition_yhwcl = parse_privacy(&msg);
    // End mutation: Producer.REPLACE_FUNC_MUTATOR


    if (ret_parse_content_disposition_yhwcl < 0){
    	return 0;
    }

    int ret_set_path_vector_uwsfs = set_path_vector(&msg, sipifmatch);
    if (ret_set_path_vector_uwsfs < 0){
    	return 0;
    }

    // End mutation: Producer.APPEND_MUTATOR


        // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from free_via_list to parse_via_oc
        struct sip_msg duzapveh;
        memset(&duzapveh, 0, sizeof(duzapveh));
        int ret_parse_privacy_bhald = parse_privacy(&duzapveh);
        if (ret_parse_privacy_bhald < 0){
        	return 0;
        }


        // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from parse_privacy to set_path_vector
        free_sipifmatch(&sipifmatch);

        int ret_set_path_vector_tglcg = set_path_vector(&duzapveh, sipifmatch);
        if (ret_set_path_vector_tglcg < 0){
        	return 0;
        }

        // End mutation: Producer.APPEND_MUTATOR

        int ret_parse_via_oc_wkwnd = parse_via_oc(&duzapveh, &via_body, NULL);
        if (ret_parse_via_oc_wkwnd < 0){
        	return 0;
        }

        // End mutation: Producer.APPEND_MUTATOR

    msg_ctx_id_set(&msg, &msg_ctx_id);

    return 0;
}