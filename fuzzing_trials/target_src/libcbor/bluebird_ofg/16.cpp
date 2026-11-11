extern "C" {
    #include "cbor.h"
    #include <stdbool.h>
    #include <stddef.h>
}

extern "C" int LLVMFuzzerTestOneInput_16(const uint8_t *data, size_t size) {
    // Ensure that the input size is sufficient for our test
    if (size < 2) {
        return 0;
    }

    // Initialize CBOR items
    cbor_item_t *array = cbor_new_definite_array(1); // Create an array with at least one slot
    cbor_item_t *item = cbor_new_int8(); // Create a new CBOR integer item
    cbor_mark_negint(item); // Mark it as a negative integer for variety

    // Extract an index from the data, ensuring it's within bounds
    size_t index = data[0] % cbor_array_allocated(array); // Use cbor_array_allocated to prevent division by zero

    // Call the function-under-test
    bool result = cbor_array_set(array, index, item);

    // Clean up
    cbor_decref(&array);
    cbor_decref(&item);

    return 0;
}