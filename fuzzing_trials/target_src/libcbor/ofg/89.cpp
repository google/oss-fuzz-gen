#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <cbor.h>

extern "C" int LLVMFuzzerTestOneInput_89(const uint8_t *data, size_t size) {
    // Check if size is greater than 0 to create a string
    if (size == 0) {
        return 0;
    }

    // Create a definite string using the fuzzing input
    cbor_item_t *item = cbor_build_stringn((const char *)data, size);

    // Ensure the item is not NULL
    if (item == NULL) {
        return 0;
    }

    // Clean up
    cbor_decref(&item);

    return 0;
}