#include <cstdint>
#include <cbor.h>

extern "C" int LLVMFuzzerTestOneInput_133(const uint8_t *data, size_t size) {
    // Initialize a CBOR parser and item
    struct cbor_load_result result;
    cbor_item_t *item = cbor_load(data, size, &result);

    // Ensure the item is not NULL and is of type integer
    if (item != nullptr && cbor_isa_uint(item)) {
        // Call the function-under-test
        uint64_t value = cbor_get_int(item);

        // Optionally, you can use the value or print it for debugging
        // printf("Extracted integer: %" PRIu64 "\n", value);
    }

    // Clean up the CBOR item
    if (item != nullptr) {
        cbor_decref(&item);
    }

    return 0;
}