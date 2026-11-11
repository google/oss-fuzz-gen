#include <stdint.h>
#include <stddef.h>
#include <cbor.h>

extern "C" int LLVMFuzzerTestOneInput_123(const uint8_t *data, size_t size) {
    // Check if the input data is not empty
    if (size == 0) {
        return 0;
    }

    // Parse the input data as a CBOR item
    struct cbor_load_result result;
    cbor_item_t *item = cbor_load(data, size, &result);

    // If the item is successfully created, perform operations with it
    if (item != NULL) {
        // Example operation: check the type of the CBOR item
        cbor_type type = cbor_typeof(item);

        // Perform additional operations based on the type if needed
        // For fuzzing purposes, you might want to manipulate or inspect the item

        // Clean up the cbor_item_t to avoid memory leaks
        cbor_decref(&item);
    }

    return 0;
}