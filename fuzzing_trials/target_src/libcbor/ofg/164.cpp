#include <stdint.h>
#include <stdlib.h>
#include <cbor.h>

extern "C" int LLVMFuzzerTestOneInput_164(const uint8_t *data, size_t size) {
    // Check if the input size is sufficient to create meaningful CBOR data
    if (size < 1) {
        return 0; // Not enough data to process
    }

    // Call the function-under-test
    cbor_item_t *item = cbor_new_indefinite_string();

    // Ensure the item is not NULL before performing operations
    if (item != NULL) {
        // Add chunks to the indefinite string using the fuzzing input data
        // Split the data into chunks to simulate realistic usage
        size_t chunk_size = size / 2; // Example: split into two chunks
        if (chunk_size > 0) {
            cbor_item_t *chunk1 = cbor_build_bytestring(data, chunk_size);
            cbor_item_t *chunk2 = cbor_build_bytestring(data + chunk_size, size - chunk_size);

            if (chunk1 != NULL) {
                cbor_string_add_chunk(item, chunk1);
                cbor_decref(&chunk1);
            }

            if (chunk2 != NULL) {
                cbor_string_add_chunk(item, chunk2);
                cbor_decref(&chunk2);
            }
        }

        // Clean up and free the item
        cbor_decref(&item);
    }

    return 0;
}