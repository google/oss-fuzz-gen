#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h> // Include for memcpy
#include <limits.h> // Include for INT_MAX
#include "/src/kamailio/src/core/parser/parse_rr.h" // Include for parse_rr_body

// Fuzzer harness
int LLVMFuzzerTestOneInput_62(const uint8_t *data, size_t size) {
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

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from parse_rr_body to decode_mime_type
    const unsigned int mjnlxmnk = -1;


    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from parse_rr_body to parse_hname2
    struct hdr_field bjydnlmq;
    memset(&bjydnlmq, 0, sizeof(bjydnlmq));
    free_allow_header(&bjydnlmq);

    char* ret_parse_hname2_qelsj = parse_hname2(mutable_data, (const char *)"w", &bjydnlmq);
    if (ret_parse_hname2_qelsj == NULL){
    	return 0;
    }

    // End mutation: Producer.APPEND_MUTATOR

    char* ret_decode_mime_type_tfftz = decode_mime_type(mutable_data, (const char *)data, &mjnlxmnk);
    if (ret_decode_mime_type_tfftz == NULL){
    	return 0;
    }

    // End mutation: Producer.APPEND_MUTATOR

    hdr_free_parsed((void **)rr);
    const int pdxwvbrs = 64;

    char* ret_parse_content_length_bwrea = parse_content_length(mutable_data, rr, &pdxwvbrs);
    if (ret_parse_content_length_bwrea == NULL){
    	return 0;
    }

    // End mutation: Producer.APPEND_MUTATOR


    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from parse_content_length to decode_mime_type
    const unsigned int jyxnxihs = -1;


    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 1 of decode_mime_type
    char* ret_decode_mime_type_gkodq = decode_mime_type(ret_parse_content_length_bwrea, (const char *)"w", &jyxnxihs);
    // End mutation: Producer.REPLACE_ARG_MUTATOR


    if (ret_decode_mime_type_gkodq == NULL){
    	return 0;
    }

    // End mutation: Producer.APPEND_MUTATOR

    free(mutable_data);
    free(rr);

    return 0;
}