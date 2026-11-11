#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h> // Include for memcpy
#include <limits.h> // Include for INT_MAX
#include "/src/kamailio/src/core/parser/parse_rr.h" // Include for parse_rr_body

// Fuzzer harness
int LLVMFuzzerTestOneInput_84(const uint8_t *data, size_t size) {
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

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from parse_rr_body to parse_retry_after
    const char dkyumkqt[1024] = "cszrd";
    const unsigned int gkxjllke = 0;
    const int xwfhxwpy = -1;

    char* ret_parse_retry_after_wtlae = parse_retry_after(mutable_data, dkyumkqt, &gkxjllke, &xwfhxwpy);
    if (ret_parse_retry_after_wtlae == NULL){
    	return 0;
    }

    // End mutation: Producer.APPEND_MUTATOR

    int ret_parse_rr_kwmve = parse_rr(NULL);
    if (ret_parse_rr_kwmve < 0){
    	return 0;
    }


    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 2 of decode_mime_type
    const unsigned int aobnpcnf = -1;
    char* ret_decode_mime_type_eulam = decode_mime_type(mutable_data, NULL, &aobnpcnf);
    // End mutation: Producer.REPLACE_ARG_MUTATOR


    if (ret_decode_mime_type_eulam == NULL){
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

    free(mutable_data);
    free(rr);

    return 0;
}