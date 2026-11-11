#include <cstdint>
#include <cstdlib>
#include <cbor.h>

extern "C" int LLVMFuzzerTestOneInput_113(const uint8_t *data, size_t size) {
    // Ensure that the size is non-zero to create a valid cbor_item_t
    if (size == 0) {
        return 0;
    }

    // Initialize a cbor_item_t object
    cbor_item_t *item = cbor_new_definite_map(size);

    // Check if the item is a map
    bool is_map = cbor_isa_map(item);

    // Clean up
    cbor_decref(&item);

    return 0;
}