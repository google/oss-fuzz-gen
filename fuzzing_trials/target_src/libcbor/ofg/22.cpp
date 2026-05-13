#include <stdint.h>
#include <stdlib.h>
#include <cbor.h>

extern "C" int LLVMFuzzerTestOneInput_22(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient to extract a uint64_t value
    if (size < sizeof(uint64_t)) {
        return 0;
    }

    // Extract a uint64_t value from the data
    uint64_t tag = *((const uint64_t *)data);

    // Move the data pointer forward and adjust the size
    data += sizeof(uint64_t);
    size -= sizeof(uint64_t);

    // Create a dummy cbor_item_t map with the remaining data
    cbor_item_t *dummy_item = cbor_new_definite_map(size);
    if (dummy_item == NULL) {
        return 0;
    }

    // Populate the map with key-value pairs from the remaining data
    for (size_t i = 0; i < size; i++) {
        cbor_item_t *key = cbor_build_uint8(i);
        cbor_item_t *value = cbor_build_uint8(data[i]);
        cbor_map_add(dummy_item, (struct cbor_pair) {
            .key = key,
            .value = value
        });
    }

    // Call the function-under-test
    cbor_item_t *result = cbor_build_tag(tag, dummy_item);

    // Clean up
    if (result != NULL) {
        cbor_decref(&result);
    }
    cbor_decref(&dummy_item);

    return 0;
}