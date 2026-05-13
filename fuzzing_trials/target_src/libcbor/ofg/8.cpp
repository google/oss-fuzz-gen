#include <cbor.h>
#include <cstdint>
#include <cstdlib>

extern "C" int LLVMFuzzerTestOneInput_8(const uint8_t *data, size_t size) {
    // Ensure that the input size is sufficient to create a CBOR item
    if (size < 1) {
        return 0;
    }

    // Create a CBOR item
    cbor_item_t *item = cbor_new_definite_array(size);

    // Populate the CBOR array with dummy data to ensure it's not NULL
    for (size_t i = 0; i < size; ++i) {
        cbor_item_t *dummy_item = cbor_build_uint8(data[i]);
        cbor_array_push(item, dummy_item);
    }

    // Call the function-under-test
    cbor_item_t **handle = cbor_array_handle(item);

    // Clean up
    cbor_decref(&item);

    return 0;
}