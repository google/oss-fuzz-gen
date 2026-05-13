#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Include the required header file for the function definition
#include "/src/kamailio/src/core/parser/parse_content.h"

// Remove the 'extern "C"' as it is not needed for C code
int LLVMFuzzerTestOneInput_64(const uint8_t *data, size_t size) {
    if (size < 3) {
        return 0; // Ensure there is enough data for all parameters
    }

    // Split the input data into three parts for the three parameters
    size_t len1 = size / 3;
    size_t len2 = size / 3;
    size_t len3 = size - len1 - len2;

    // Allocate memory for the first parameter (const char *)
    char *param1 = (char *)malloc(len1 + 1);
    if (!param1) {
        return 0;
    }
    memcpy(param1, data, len1);
    param1[len1] = '\0'; // Null-terminate the string

    // Allocate memory for the second parameter (const char *)
    char *param2 = (char *)malloc(len2 + 1);
    if (!param2) {
        free(param1);
        return 0;
    }
    memcpy(param2, data + len1, len2);
    param2[len2] = '\0'; // Null-terminate the string

    // Allocate memory for the third parameter (unsigned int *)
    unsigned int *param3 = (unsigned int *)malloc(sizeof(unsigned int));
    if (!param3) {
        free(param1);
        free(param2);
        return 0;
    }
    memcpy(param3, data + len1 + len2, len3 < sizeof(unsigned int) ? len3 : sizeof(unsigned int));

    // Call the function-under-test
    char *result = decode_mime_type(param1, param2, param3);

    // Clean up
    free(param1);
    free(param2);
    free(param3);

    // If the result is dynamically allocated, free it
    if (result) {
        free(result);
    }

    return 0;
}