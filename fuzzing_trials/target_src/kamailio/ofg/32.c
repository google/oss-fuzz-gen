#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Include the necessary header for the function under test
#include "/src/kamailio/src/core/parser/parse_methods.c"

// Function under test
int parse_methods(const str *const _body, unsigned int *const _methods);

int LLVMFuzzerTestOneInput_32(const uint8_t *data, size_t size) {
    // Ensure that the data size is sufficient to create a valid str object
    if (size < sizeof(unsigned int) + 1) {
        return 0;
    }

    // Allocate memory for the str object and initialize it
    str input_str;
    input_str.s = (const char *)data;
    input_str.len = size - sizeof(unsigned int);

    // Extract options from the input data
    unsigned int options;
    memcpy(&options, data + input_str.len, sizeof(unsigned int));

    // Call the function under test
    parse_methods(&input_str, &options);

    return 0;
}