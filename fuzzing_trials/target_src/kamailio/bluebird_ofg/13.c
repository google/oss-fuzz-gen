#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "/src/kamailio/src/core/parser/parse_identity.h"

// Function-under-test
void parse_identity(char *param1, char *param2, struct identity_body *body);

int LLVMFuzzerTestOneInput_13(const uint8_t *data, size_t size) {
    if (size < 2) {
        return 0;
    }

    // Allocate memory for the first two parameters
    char *param1 = (char *)malloc(size / 2 + 1);
    char *param2 = (char *)malloc(size / 2 + 1);

    // Ensure memory allocation was successful
    if (param1 == NULL || param2 == NULL) {
        free(param1);
        free(param2);
        return 0;
    }

    // Copy data into the parameters
    memcpy(param1, data, size / 2);
    param1[size / 2] = '\0'; // Null-terminate the string
    memcpy(param2, data + size / 2, size / 2);
    param2[size / 2] = '\0'; // Null-terminate the string

    // Initialize the identity_body structure
    struct identity_body body;
    memset(&body, 0, sizeof(body));

    // Call the function-under-test
    parse_identity(param1, param2, &body);

    // Free allocated memory
    free(param1);
    free(param2);

    return 0;
}