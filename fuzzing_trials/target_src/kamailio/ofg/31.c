#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "/src/kamailio/src/core/parser/parse_identityinfo.h"

// Function signature to be fuzzed
void parse_identityinfo(char *param1, char *param2, struct identityinfo_body *info);

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_31(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for splitting into two strings
    if (size < 2) {
        return 0;
    }

    // Calculate sizes for the two strings
    size_t half_size = size / 2;

    // Allocate memory for the strings, ensuring they are null-terminated
    char *param1 = (char *)malloc(half_size + 1);
    char *param2 = (char *)malloc(size - half_size + 1);

    if (param1 == NULL || param2 == NULL) {
        free(param1);
        free(param2);
        return 0;
    }

    // Copy data into the strings and null-terminate them
    memcpy(param1, data, half_size);
    param1[half_size] = '\0';

    memcpy(param2, data + half_size, size - half_size);
    param2[size - half_size] = '\0';

    // Initialize the identityinfo_body structure
    struct identityinfo_body info;
    memset(&info, 0, sizeof(info)); // Initialize all fields to 0

    // Call the function-under-test
    parse_identityinfo(param1, param2, &info);

    // Clean up allocated memory
    free(param1);
    free(param2);

    return 0;
}

#ifdef __cplusplus
}
#endif