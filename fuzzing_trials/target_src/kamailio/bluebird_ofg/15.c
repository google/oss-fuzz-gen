#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h> // Include for memcpy
#include <limits.h> // Include for INT_MAX
#include "/src/kamailio/src/core/parser/parse_rr.h" // Include for parse_rr_body

// Fuzzer harness
int LLVMFuzzerTestOneInput_15(const uint8_t *data, size_t size) {
    // Ensure size is not zero to avoid passing NULL to parse_rr_body
    if (size == 0) {
        return 0;
    }

    // Allocate memory for rr_t pointer
    rr_t *rr = (rr_t *)malloc(sizeof(rr_t));
    if (rr == NULL) {
        return 0; // Failed to allocate memory
    }

    // Initialize the rr_t structure to avoid uninitialized memory access
    memset(rr, 0, sizeof(rr_t));

    // Copy the data into a mutable buffer
    char *mutable_data = (char *)malloc(size + 1);
    if (mutable_data == NULL) {
        free(rr);
        return 0; // Failed to allocate memory
    }
    memcpy(mutable_data, data, size);
    mutable_data[size] = '\0'; // Null-terminate to ensure it's a valid C-string

    // Call the function under test
    // Ensure the length passed is within bounds
    if (size > INT_MAX) {
        free(mutable_data);
        free(rr);
        return 0; // Avoid integer overflow
    }
    // Ensure rr is passed by reference correctly
    parse_rr_body(mutable_data, (int)size, rr);

    // Clean up

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from parse_rr_body to parse_uri
    struct sip_uri swzsdabb;

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from parse_rr_body to parse_to_body
    hdr_free_parsed((void **)rr);
    struct hdr_field zyjepmkp;

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from hdr_free_parsed to get_hdr_field
    struct hdr_field xopgvdaf;
    memset(&xopgvdaf, 0, sizeof(xopgvdaf));
    free_allow_header(&xopgvdaf);
    const char crpnzeyy[1024] = "entrt";

    char* ret_get_hdr_field_vavyd = get_hdr_field(rr, crpnzeyy, &xopgvdaf);
    if (ret_get_hdr_field_vavyd == NULL){
    	return 0;
    }

    // End mutation: Producer.APPEND_MUTATOR

    memset(&zyjepmkp, 0, sizeof(zyjepmkp));
    free_allow_header(&zyjepmkp);


    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from free_allow_header to print_rr_body

    int ret_print_rr_body_ynaov = print_rr_body(&xopgvdaf, NULL, VIA_PARAM_F_QUOTED, NULL);
    if (ret_print_rr_body_ynaov < 0){
    	return 0;
    }

    // End mutation: Producer.APPEND_MUTATOR

    char* ret_parse_to_body_oucsy = parse_to_body(mutable_data, rr, &zyjepmkp);
    if (ret_parse_to_body_oucsy == NULL){
    	return 0;
    }

    // End mutation: Producer.APPEND_MUTATOR


    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from parse_to_body to decode_mime_type
    struct sip_msg tcixajgh;

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from parse_to_body to get_hdr_field
    int ret_parse_sipifmatch_gxkje = parse_sipifmatch(&zyjepmkp);
    if (ret_parse_sipifmatch_gxkje < 0){
    	return 0;
    }

    char* ret_get_hdr_field_vatpi = get_hdr_field((const char *)"r", ret_parse_to_body_oucsy, &zyjepmkp);
    if (ret_get_hdr_field_vatpi == NULL){
    	return 0;
    }

    // End mutation: Producer.APPEND_MUTATOR

    memset(&tcixajgh, 0, sizeof(tcixajgh));
    int ret_parse_allow_uqinl = parse_allow(&tcixajgh);
    if (ret_parse_allow_uqinl < 0){
    	return 0;
    }

    char* ret_decode_mime_type_yemgd = decode_mime_type((const char *)"w", ret_parse_to_body_oucsy, (const unsigned int *)&ret_parse_allow_uqinl);
    if (ret_decode_mime_type_yemgd == NULL){
    	return 0;
    }

    // End mutation: Producer.APPEND_MUTATOR

    memset(&swzsdabb, 0, sizeof(swzsdabb));

    int ret_parse_uri_urtis = parse_uri(mutable_data, size, &swzsdabb);
    if (ret_parse_uri_urtis < 0){
    	return 0;
    }

    // End mutation: Producer.APPEND_MUTATOR


    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from parse_uri to parse_priv_value
    const sip_msg_t dwumeowj;
    memset(&dwumeowj, 0, sizeof(dwumeowj));
    int ret_msg_set_time_lgkgp = msg_set_time(&dwumeowj);
    if (ret_msg_set_time_lgkgp < 0){
    	return 0;
    }

    unsigned int ret_parse_priv_value_kipck = parse_priv_value(mutable_data, 64, (unsigned int *)&ret_msg_set_time_lgkgp);
    if (ret_parse_priv_value_kipck < 0){
    	return 0;
    }

    // End mutation: Producer.APPEND_MUTATOR

    free(mutable_data);
    free(rr);

    return 0;
}