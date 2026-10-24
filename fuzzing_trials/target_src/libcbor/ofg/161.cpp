#include <cstdint>
#include <cstdlib>
#include <cbor.h>

extern "C" {
    size_t cbor_array_size(const cbor_item_t *);
}

extern "C" int LLVMFuzzerTestOneInput_161(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0; // No data to process
    }

    // Create a CBOR item
    cbor_item_t *item = cbor_new_definite_array(size);

    // Populate the CBOR array with dummy data
    for (size_t i = 0; i < size; ++i) {
        cbor_item_t *dummy_item = cbor_build_uint8(data[i]);
        cbor_array_push(item, dummy_item);
    }

    // Call the function-under-test
    size_t array_size = cbor_array_size(item);

    // Clean up
    cbor_decref(&item);

    return 0;
}