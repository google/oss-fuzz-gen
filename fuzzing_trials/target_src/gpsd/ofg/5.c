#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

// Function-under-test declaration
bool netgnss_uri_check(const char *uri);

int LLVMFuzzerTestOneInput_5(const uint8_t *data, size_t size) {
    // Ensure the data is null-terminated to safely use it as a C string
    char *uri = (char *)malloc(size + 1);
    if (uri == NULL) {
        return 0; // Exit if memory allocation fails
    }

    // Copy the input data into the uri buffer and null-terminate it
    memcpy(uri, data, size);
    uri[size] = '\0';

    // Call the function-under-test
    netgnss_uri_check(uri);

    // Free the allocated memory
    free(uri);

    return 0;
}