#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h> // Include for memcpy
#include <limits.h> // Include for INT_MAX
#include "/src/kamailio/src/core/parser/parse_rr.h" // Include for parse_rr_body

// Fuzzer harness
int LLVMFuzzerTestOneInput_37(const uint8_t *data, size_t size) {
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

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from parse_rr_body to parse_msg
    struct sip_msg xevujzlq;
    memset(&xevujzlq, 0, sizeof(xevujzlq));
    int ret_parse_privacy_kcwlk = parse_privacy(&xevujzlq);
    if (ret_parse_privacy_kcwlk < 0){
    	return 0;
    }

    int ret_parse_msg_hxlvq = parse_msg(mutable_data, OPTIONS_LEN, &xevujzlq);
    if (ret_parse_msg_hxlvq < 0){
    	return 0;
    }

    // End mutation: Producer.APPEND_MUTATOR

    memset(&zfxblhok, 0, sizeof(zfxblhok));
    int ret_parse_orig_ruri_nbkey = parse_orig_ruri(&zfxblhok);
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