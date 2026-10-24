extern "C" {
#include <cbor.h>
}

extern "C" int LLVMFuzzerTestOneInput_67(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient for testing
    if (size < 2) {
        return 0;
    }

    // Create a CBOR decoder context
    struct cbor_load_result load_result;
    cbor_item_t *item = cbor_load(data, size, &load_result);

    // Check if the item is a valid CBOR array
    if (item != NULL && cbor_isa_array(item)) {
        // Get the number of elements in the array
        size_t array_size = cbor_array_size(item);

        // Iterate over the array and access each element
        for (size_t i = 0; i < array_size; i++) {
            // Call the function-under-test
            cbor_item_t *element = cbor_array_get(item, i);

            // Perform any additional operations on the element if needed
            // For this fuzzing harness, we are just calling the function
            (void)element; // Suppress unused variable warning
        }
    }

    // Decrement reference count and free the CBOR item
    if (item != NULL) {
        cbor_decref(&item);
    }

    return 0;
}