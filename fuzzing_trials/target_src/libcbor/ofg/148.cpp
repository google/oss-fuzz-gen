#include <cbor.h>
#include <stdint.h>
#include <stdlib.h>

extern "C" {
    struct cbor_pair * cbor_map_handle(const cbor_item_t *);
}

extern "C" int LLVMFuzzerTestOneInput_148(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    // Initialize a CBOR item with the input data
    cbor_item_t *item = cbor_new_definite_map(size);

    // Populate the CBOR map with dummy key-value pairs
    for (size_t i = 0; i < size; ++i) {
        cbor_item_t *key = cbor_build_uint8(data[i]);
        cbor_item_t *value = cbor_build_uint8(data[size - i - 1]);
        cbor_map_add(item, (struct cbor_pair) { .key = key, .value = value });
    }

    // Call the function-under-test
    struct cbor_pair *result = cbor_map_handle(item);

    // Clean up
    cbor_decref(&item);

    // Return 0 to indicate successful execution
    return 0;
}