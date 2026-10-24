#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "/src/kamailio/src/core/parser/parse_sipifmatch.c"
#include "/src/kamailio/src/core/str.h"  // Include the correct header for 'str'

// Function prototype for the function-under-test
void free_sipifmatch(str **s);

int LLVMFuzzerTestOneInput_37(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for meaningful test
    if (size < 1) {
        return 0; // Exit if input size is too small
    }

    // Allocate memory for the str structure
    str *s = (str *)malloc(sizeof(str));
    if (s == NULL) {
        return 0; // Exit if memory allocation fails
    }

    // Allocate memory for the string data and copy input data
    s->s = (char *)malloc(size + 1); // +1 for null-terminator
    if (s->s == NULL) {
        free(s);
        return 0; // Exit if memory allocation fails
    }

    memcpy(s->s, data, size);
    s->s[size] = '\0'; // Null-terminate the string
    s->len = size;

    // Create a pointer to the str structure
    str *s_ptr = s;

    // Call the function-under-test with a non-null input
    free_sipifmatch(&s_ptr);

    // Free the allocated memory if not freed by the function-under-test
    if (s_ptr != NULL) {
        free(s_ptr->s);
        free(s_ptr);
    }

    return 0;
}