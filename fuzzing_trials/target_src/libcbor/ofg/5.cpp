#include <cstdint>
#include <cstddef>
#include <cbor.h>

// Ensure that the C headers are correctly linked in C++ code
extern "C" {
    size_t cbor_string_codepoint_count(const cbor_item_t *);
}

extern "C" int LLVMFuzzerTestOneInput_5(const uint8_t *data, size_t size) {
    // Create a CBOR item from the input data
    struct cbor_load_result result;
    cbor_item_t *item = cbor_load(data, size, &result);

    // Ensure the item is not NULL and is a CBOR string
    if (item != NULL && cbor_isa_string(item)) {
        // Call the function under test
        size_t count = cbor_string_codepoint_count(item);
        
        // Use the result to avoid compiler optimizations that might skip the function call
        (void)count;
    }

    // Clean up the CBOR item
    if (item != NULL) {
        cbor_decref(&item);
    }

    return 0;
}