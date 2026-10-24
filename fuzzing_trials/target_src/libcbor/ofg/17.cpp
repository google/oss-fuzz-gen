#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cassert>
#include <cstdlib>
#include "cbor.h"  // Assuming the CBOR library provides this header

extern "C" {
    size_t cbor_serialize_array(const cbor_item_t *, unsigned char *, size_t);
}

extern "C" int LLVMFuzzerTestOneInput_17(const uint8_t *data, size_t size) {
    // Ensure size is sufficient for testing
    if (size < 2) return 0;

    // Determine the number of items in the array
    size_t num_items = data[0] % 10; // Limit to 10 items for simplicity
    if (size < num_items + 1) return 0;

    // Create a CBOR array item
    cbor_item_t *array = cbor_new_definite_array(num_items);
    if (!array) return 0;

    // Add integers to the array
    for (size_t i = 0; i < num_items; ++i) {
        cbor_item_t *int_item = cbor_build_uint8(data[i + 1]);
        if (!int_item) {
            cbor_decref(&array);
            return 0;
        }
        cbor_array_push(array, int_item);
        cbor_decref(&int_item);
    }

    // Prepare a buffer for serialization
    size_t buffer_size = 256; // Arbitrary buffer size
    unsigned char *buffer = (unsigned char *)malloc(buffer_size);
    if (!buffer) {
        cbor_decref(&array);
        return 0;
    }

    // Call the function under test
    size_t serialized_size = cbor_serialize_array(array, buffer, buffer_size);

    // Clean up
    free(buffer);
    cbor_decref(&array);

    return 0;
}