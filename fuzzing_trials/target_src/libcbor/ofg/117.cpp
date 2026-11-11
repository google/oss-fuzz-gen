extern "C" {
#include <cbor.h>
}

extern "C" int LLVMFuzzerTestOneInput_117(const uint8_t *data, size_t size) {
    // Ensure size is sufficient to create a cbor_item_t object
    if (size < 1) {
        return 0;
    }

    // Create a CBOR item
    cbor_item_t *item = cbor_new_definite_bytestring();
    
    // Initialize the CBOR item with some data
    cbor_bytestring_set_handle(item, (unsigned char *)data, size);

    // Call the function-under-test
    cbor_item_t *result = cbor_incref(item);

    // Ensure result is not the same as item to avoid use-after-free
    if (result != item) {
        // Clean up
        cbor_decref(&item);   // Decrement the reference count of the item first
        cbor_decref(&result); // Then decrement the reference count of the result
    } else {
        // If result is the same as item, only decrement once
        cbor_decref(&item);
    }

    return 0;
}