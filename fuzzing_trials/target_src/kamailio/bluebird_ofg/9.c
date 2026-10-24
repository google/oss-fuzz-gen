#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h> // Include for memcpy
#include <limits.h> // Include for INT_MAX
#include "/src/kamailio/src/core/parser/parse_rr.h" // Include for parse_rr_body

// Fuzzer harness
int LLVMFuzzerTestOneInput_9(const uint8_t *data, size_t size) {
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

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from parse_rr_body to parse_content_length
    struct sip_msg zfxblhok;

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from parse_rr_body to parse_hname2
    struct hdr_field myektguf;
    memset(&myektguf, 0, sizeof(myektguf));
    int ret_parse_allow_header_uupsj = parse_allow_header(&myektguf);
    if (ret_parse_allow_header_uupsj < 0){
    	return 0;
    }


    // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function parse_hname2 with parse_to_body

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from parse_allow_header to clean_hdr_field

    clean_hdr_field(&myektguf);

    // End mutation: Producer.APPEND_MUTATOR

    char* ret_parse_hname2_wkjzl = parse_to_body((const char *)"w", mutable_data, &myektguf);
    // End mutation: Producer.REPLACE_FUNC_MUTATOR


    if (ret_parse_hname2_wkjzl == NULL){
    	return 0;
    }

    // End mutation: Producer.APPEND_MUTATOR


    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from parse_to_body to parse_identity

    parse_identity((char *)"w", ret_parse_hname2_wkjzl, NULL);

    // End mutation: Producer.APPEND_MUTATOR

    memset(&zfxblhok, 0, sizeof(zfxblhok));

    // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function parse_orig_ruri with parse_content_disposition
    int ret_parse_orig_ruri_nbkey = parse_content_disposition(&zfxblhok);
    // End mutation: Producer.REPLACE_FUNC_MUTATOR


    if (ret_parse_orig_ruri_nbkey < 0){
    	return 0;
    }

    char* ret_parse_content_length_dblbu = parse_content_length((const char *)"w", mutable_data, &ret_parse_orig_ruri_nbkey);
    if (ret_parse_content_length_dblbu == NULL){
    	return 0;
    }

    // End mutation: Producer.APPEND_MUTATOR

    free(mutable_data);
    free(rr);

    return 0;
}