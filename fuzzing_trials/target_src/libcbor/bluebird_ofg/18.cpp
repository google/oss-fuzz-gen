#include "cbor.h"
#include "cstdint"
#include "cstdlib"

extern "C" {
    size_t cbor_map_allocated(const cbor_item_t *);
}

extern "C" int LLVMFuzzerTestOneInput_18(const uint8_t *data, size_t size) {
    if (size < 2) {
        return 0; // Not enough data to proceed
    }

    // Determine the number of key-value pairs based on the input size
    size_t num_pairs = size / 2;

    // Create a cbor_item_t object for a map with num_pairs

    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 0 of cbor_new_definite_map
    cbor_item_t *item = cbor_new_definite_map(1);
    // End mutation: Producer.REPLACE_ARG_MUTATOR


    if (!item) {
        return 0; // Failed to create cbor item
    }

    // Add key-value pairs to the map
    for (size_t i = 0; i < num_pairs; ++i) {
        cbor_item_t *key = cbor_build_uint8(data[i * 2]);
        cbor_item_t *value = cbor_build_uint8(data[i * 2 + 1]);
        if (!cbor_map_add(item, (struct cbor_pair){.key = key, .value = value})) {
            cbor_decref(&key);
            cbor_decref(&value);
            continue; // Skip this pair if adding fails
        }
    }

    // Call the function-under-test
    size_t allocated = cbor_map_allocated(item);

    // Clean up
    cbor_decref(&item);

    return 0;
}