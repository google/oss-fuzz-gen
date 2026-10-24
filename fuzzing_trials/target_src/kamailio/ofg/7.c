#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "/src/kamailio/src/core/parser/parse_identity.h" // Include the header for parse_identity

// Function-under-test
void parse_identity(char *param1, char *param2, struct identity_body *body);

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_7(const uint8_t *data, size_t size) {
    // Ensure there's enough data to work with
    if (size < 2) {
        return 0;
    }

    // Allocate memory for the parameters
    char *param1 = (char *)malloc(size / 2 + 1);
    char *param2 = (char *)malloc(size / 2 + 1);
    struct identity_body body;

    // Ensure the allocations were successful
    if (param1 == NULL || param2 == NULL) {
        free(param1);
        free(param2);
        return 0;
    }

    // Copy the data into param1 and param2, ensuring null-termination
    memcpy(param1, data, size / 2);
    param1[size / 2] = '\0';
    memcpy(param2, data + size / 2, size / 2);
    param2[size / 2] = '\0';

    // Initialize the identity_body structure with some values
    body.error = 0;
    body.ballocated = 0;
    body.hash.s = NULL;
    body.hash.len = 0;

    // Call the function-under-test
    parse_identity(param1, param2, &body);

    // Clean up
    free(param1);
    free(param2);

    return 0;
}

#ifdef __cplusplus
}
#endif