#include <cbor.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

extern "C" int LLVMFuzzerTestOneInput_100(const uint8_t *data, size_t size) {
    // Ensure the data is null-terminated and non-empty
    if (size == 0) {
        return 0;
    }

    // Allocate memory for a null-terminated string
    char *inputString = (char *)malloc(size + 1);
    if (inputString == NULL) {
        return 0;
    }

    // Copy the data into the string and null-terminate it
    memcpy(inputString, data, size);
    inputString[size] = '\0';

    // Call the function-under-test
    cbor_item_t *item = cbor_build_string(inputString);

    // Free the allocated cbor_item_t if it was created
    if (item != NULL) {
        cbor_decref(&item);
    }

    // Free the allocated string
    free(inputString);

    return 0;
}