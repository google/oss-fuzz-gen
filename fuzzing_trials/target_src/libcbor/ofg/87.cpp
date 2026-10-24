#include <cbor.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

extern "C" int LLVMFuzzerTestOneInput_87(const uint8_t *data, size_t size) {
    // Ensure the data is not empty and size is sufficient
    if (size > 0) {
        // Create a cbor_item_t from the input data
        cbor_item_t *data_item = cbor_build_bytestring(data, size);

        // Initialize a cbor_item_t pointer for an array
        cbor_item_t *item = cbor_new_definite_array(1);

        // Append the data_item to the array
        cbor_array_push(item, data_item);

        // Call additional CBOR functions to increase code coverage
        bool is_negint = cbor_isa_negint(data_item);
        bool is_bytestring = cbor_isa_bytestring(data_item);
        size_t array_size = cbor_array_size(item);

        // Print the results to ensure the functions are being called
        // (In real fuzzing, these prints would be removed)
        printf("is_negint: %d, is_bytestring: %d, array_size: %zu\n", is_negint, is_bytestring, array_size);

        // Clean up
        cbor_decref(&data_item);
        cbor_decref(&item);
    }

    return 0;
}