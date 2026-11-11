#include <cstdint>
#include <cbor.h>
#include <cbor/encoding.h>

extern "C" int LLVMFuzzerTestOneInput_144(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0; // No data to process
    }

    // Attempt to parse the input data as a CBOR item
    struct cbor_load_result result;
    cbor_item_t *item = cbor_load(data, size, &result);

    // Ensure the item is not NULL before attempting to use it
    if (item != NULL) {
        // Perform any additional operations or checks on the item if necessary

        // Decrement the reference count and free the item
        cbor_decref(&item);
    }

    return 0;
}