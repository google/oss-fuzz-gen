#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <cbor.h>

extern "C" {
    bool cbor_array_is_definite(const cbor_item_t *);
}

extern "C" int LLVMFuzzerTestOneInput_139(const uint8_t *data, size_t size) {
    // Ensure the data size is non-zero to create a CBOR item
    if (size == 0) {
        return 0;
    }

    // Create a dummy CBOR item
    cbor_item_t *item = cbor_new_definite_array(size);

    // Populate the CBOR array with some dummy data
    for (size_t i = 0; i < size; i++) {
        cbor_item_t *dummy_data = cbor_build_uint8(data[i]);
        cbor_array_push(item, dummy_data);
        cbor_decref(&dummy_data);
    }

    // Call the function-under-test
    bool result = cbor_array_is_definite(item);

    // Clean up
    cbor_decref(&item);

    return 0;
}