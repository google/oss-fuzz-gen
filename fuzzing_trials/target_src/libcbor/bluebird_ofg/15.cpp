#include "cbor.h"
#include "cstdint"
#include "cstdlib"

extern "C" {
    size_t cbor_map_allocated(const cbor_item_t *);
}

extern "C" int LLVMFuzzerTestOneInput_15(const uint8_t *data, size_t size) {
    if (size < 2) {
        return 0; // Not enough data to proceed
    }

    // Determine the number of key-value pairs based on the input size
    size_t num_pairs = size / 2;

    // Create a cbor_item_t object for a map with num_pairs
    cbor_item_t *item = cbor_new_definite_map(num_pairs);
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

    // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function cbor_map_allocated with cbor_serialized_size
    size_t allocated = cbor_serialized_size(item);
    // End mutation: Producer.REPLACE_FUNC_MUTATOR



    // Clean up

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from cbor_serialized_size to cbor_build_negint32

    cbor_item_t* ret_cbor_build_negint32_nsglb = cbor_build_negint32((uint32_t )allocated);
    if (ret_cbor_build_negint32_nsglb == NULL){
    	return 0;
    }

    // End mutation: Producer.APPEND_MUTATOR

    cbor_decref(&item);

    return 0;
}