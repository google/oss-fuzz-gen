#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h> // Include for memcpy
#include <limits.h> // Include for INT_MAX
#include "/src/kamailio/src/core/parser/parse_rr.h" // Include for parse_rr_body

// Fuzzer harness
int LLVMFuzzerTestOneInput_57(const uint8_t *data, size_t size) {
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

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from parse_rr_body to parse_fline
    struct msg_start ziydrhlt;

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from parse_rr_body to parse_params2
    param_hooks_t ulddmdqj;

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from parse_rr_body to parse_sip_header_name
    int ret_free_diversion_body_rgjgn = free_diversion_body(NULL);
    if (ret_free_diversion_body_rgjgn < 0){
    	return 0;
    }
    const hdr_field_t xzwdvaof;
    memset(&xzwdvaof, 0, sizeof(xzwdvaof));

    char* ret_parse_sip_header_name_smknu = parse_sip_header_name(mutable_data, (const char *)data, &xzwdvaof, 0, ret_free_diversion_body_rgjgn);
    if (ret_parse_sip_header_name_smknu == NULL){
    	return 0;
    }

    // End mutation: Producer.APPEND_MUTATOR

    memset(&ulddmdqj, 0, sizeof(ulddmdqj));

    int ret_parse_params2_dcprw = parse_params2(NULL, 0, &ulddmdqj, NULL, *mutable_data);
    if (ret_parse_params2_dcprw < 0){
    	return 0;
    }

    // End mutation: Producer.APPEND_MUTATOR

    memset(&ziydrhlt, 0, sizeof(ziydrhlt));

    char* ret_parse_fline_aynjd = parse_fline(mutable_data, mutable_data, &ziydrhlt);
    if (ret_parse_fline_aynjd == NULL){
    	return 0;
    }

    // End mutation: Producer.APPEND_MUTATOR

    free(mutable_data);
    free(rr);

    return 0;
}