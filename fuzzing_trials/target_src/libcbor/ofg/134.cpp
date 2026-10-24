#include <cstdint>
#include <cstdlib>
#include <cbor.h>

extern "C" int LLVMFuzzerTestOneInput_134(const uint8_t *data, size_t size) {
    // Attempt to parse the input data as a CBOR item
    struct cbor_load_result result;
    cbor_item_t *item = cbor_load(data, size, &result);

    // If the item is successfully parsed, perform operations
    if (item != NULL) {
        // Example operation: check if the item is an integer and retrieve its value
        if (cbor_isa_uint(item)) {
            uint64_t value = cbor_get_int(item);
            // Use the value to avoid compiler optimizations removing the call
            (void)value;
        }

        // Clean up
        cbor_decref(&item);
    }

    return 0;
}