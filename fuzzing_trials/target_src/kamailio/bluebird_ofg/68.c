#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "/src/kamailio/src/core/parser/parse_hname2.c"
#include "/src/kamailio/src/core/parser/hf.h"
#include "/src/kamailio/src/core/str.h"

// Function-under-test
// The function signature has been updated to match the one in parse_hname2.c
char *parse_hname2_str(str *const hbuf, hdr_field_t *const hdr);

int LLVMFuzzerTestOneInput_68(const uint8_t *data, size_t size) {
    // Ensure that size is sufficient to create a str and hdr_field_t
    if (size < sizeof(hdr_field_t) + 1) {
        return 0;
    }

    // Initialize str
    str input_str;
    input_str.s = (char *)malloc(size - sizeof(hdr_field_t));
    if (input_str.s == NULL) {
        return 0; // Handle memory allocation failure
    }
    memcpy(input_str.s, data, size - sizeof(hdr_field_t));
    input_str.len = size - sizeof(hdr_field_t);

    // Initialize hdr_field_t
    hdr_field_t hdr_field;
    memset(&hdr_field, 0, sizeof(hdr_field_t)); // Ensure hdr_field is initialized
    memcpy(&hdr_field, data + input_str.len, sizeof(hdr_field_t));

    // Call the function-under-test
    char *result = parse_hname2_str(&input_str, &hdr_field);

    // Free the allocated memory for input_str.s
    free(input_str.s);

    // Free the result if necessary
    // Ensure that the result is not a pointer to input_str.s to avoid double-free
    if (result != NULL && result != input_str.s) {
        free(result);
    }

    return 0;
}