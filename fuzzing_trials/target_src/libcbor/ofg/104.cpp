#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

// Assuming the cbor_item_t structure and cbor_intermediate_decref function are defined in these headers
extern "C" {
    #include "cbor.h"
}

// Fuzzing harness for cbor_intermediate_decref
extern "C" int LLVMFuzzerTestOneInput_104(const uint8_t *data, size_t size) {
    // Allocate memory for a cbor_item_t object
    cbor_item_t *item = cbor_new_definite_map(1); // Create a new CBOR map with one pair

    if (item == NULL) {
        return 0; // If allocation fails, exit early
    }

    // Add a dummy key-value pair to the map
    cbor_item_t *key = cbor_build_uint8(0); // Key as an unsigned 8-bit integer
    cbor_item_t *value = cbor_build_uint8(0); // Value as an unsigned 8-bit integer
    cbor_map_add(item, (struct cbor_pair){ .key = key, .value = value });

    // Call the function under test
    cbor_intermediate_decref(item);

    // Note: No need to manually free 'item', as cbor_intermediate_decref should handle it

    return 0;
}