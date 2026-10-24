#include "cbor.h"
#include "cstdint"
#include "cstdlib"

extern "C" {
    size_t cbor_map_allocated(const cbor_item_t *);
}

extern "C" int LLVMFuzzerTestOneInput_32(const uint8_t *data, size_t size) {
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

        // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function cbor_build_uint8 with cbor_build_ctrl
        cbor_item_t *value = cbor_build_ctrl(data[i * 2 + 1]);
        // End mutation: Producer.REPLACE_FUNC_MUTATOR



        // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from cbor_build_ctrl to cbor_float_get_float

        double ret_cbor_float_get_float_jfaan = cbor_float_get_float(value);
        if (ret_cbor_float_get_float_jfaan < 0){
        	return 0;
        }

        // End mutation: Producer.APPEND_MUTATOR

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
    cbor_decref(&item);

    return 0;
}