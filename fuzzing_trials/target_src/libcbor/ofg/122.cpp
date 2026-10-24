#include <stdint.h>
#include <stddef.h>
#include <cbor.h>

extern "C" int LLVMFuzzerTestOneInput_122(const uint8_t *data, size_t size) {
    // Ensure there's data to process
    if (size == 0) {
        return 0;
    }

    // Create a CBOR parser and value
    struct cbor_load_result result;
    cbor_item_t *item = cbor_load(data, size, &result);

    // Check if the item is not NULL and perform some operations
    if (item != NULL) {
        // Perform operations on the cbor_item_t object
        // For example, we can check the type and refcount
        if (cbor_isa_bytestring(item) && cbor_bytestring_is_indefinite(item)) {
            // Do something with the item if needed
        }

        // Decrease the reference count and free the item
        cbor_decref(&item);
    }

    return 0;
}