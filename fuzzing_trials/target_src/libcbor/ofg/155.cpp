#include <cstdint>
#include <cbor.h>

extern "C" {
    bool cbor_array_is_indefinite(const cbor_item_t *);
}

extern "C" int LLVMFuzzerTestOneInput_155(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }

    // Create a cbor_item_t object from the input data
    struct cbor_item_t *item = cbor_new_definite_array(size);

    // Populate the cbor_item_t with data
    for (size_t i = 0; i < size; ++i) {
        cbor_array_push(item, cbor_build_uint8(data[i]));
    }

    // Call the function-under-test
    bool result = cbor_array_is_indefinite(item);

    // Clean up
    cbor_decref(&item);

    return 0;
}