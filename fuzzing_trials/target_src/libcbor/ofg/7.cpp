#include <stdint.h>
#include <stdbool.h>
#include <cbor.h>

extern "C" int LLVMFuzzerTestOneInput_7(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient to read at least one byte
    if (size == 0) {
        return 0;
    }

    // Use the data to create a CBOR item
    cbor_item_t *item = cbor_new_definite_map(size);

    // Populate the map with data
    for (size_t i = 0; i < size; i++) {
        cbor_item_t *key = cbor_build_uint8(i);
        cbor_item_t *value = cbor_build_uint8(data[i]);
        cbor_map_add(item, (struct cbor_pair) {
            .key = cbor_move(key),
            .value = cbor_move(value)
        });
    }

    // Call the function-under-test
    cbor_item_t *result = cbor_build_bool(cbor_map_size(item) % 2 == 0);

    // Free the result and item if they are not NULL
    if (result != NULL) {
        cbor_decref(&result);
    }
    if (item != NULL) {
        cbor_decref(&item);
    }

    return 0;
}