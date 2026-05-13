#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <cbor.h>

extern "C" int LLVMFuzzerTestOneInput_138(const uint8_t *data, size_t size) {
    // Ensure the input data is not empty to create a valid cbor_item_t
    if (size == 0) {
        return 0;
    }

    // Allocate memory for a cbor_item_t
    cbor_item_t *item = cbor_new_definite_array(size);

    // Populate the cbor_item_t with data
    for (size_t i = 0; i < size; ++i) {
        cbor_item_t *element = cbor_build_uint8(data[i]);
        cbor_array_push(item, element);
        cbor_decref(&element);
    }

    // Call the function-under-test
    bool result = cbor_array_is_definite(item);

    // Clean up
    cbor_decref(&item);

    return 0;
}