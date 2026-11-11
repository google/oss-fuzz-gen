#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <cbor.h>

extern "C" {
    bool cbor_array_is_indefinite(const cbor_item_t *);
}

extern "C" int LLVMFuzzerTestOneInput_156(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    // Initialize a CBOR item
    cbor_item_t *item = cbor_new_definite_array(size);

    // Populate the CBOR array with data
    for (size_t i = 0; i < size; i++) {
        cbor_item_t *element = cbor_build_uint8(data[i]);
        cbor_array_push(item, element);
        cbor_decref(&element);
    }

    // Call the function-under-test
    bool result = cbor_array_is_indefinite(item);

    // Clean up
    cbor_decref(&item);

    return 0;
}