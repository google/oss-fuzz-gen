#include "cstdint"
#include <cstddef>

// Wrap the libcbor includes and function calls in extern "C" to ensure proper linkage
extern "C" {
    #include "cbor.h"
}

extern "C" int LLVMFuzzerTestOneInput_11(const uint8_t *data, size_t size) {
    // Ensure the size is large enough to create a cbor_item_t
    if (size < sizeof(cbor_item_t)) {
        return 0;
    }

    // Create a cbor_item_t object
    cbor_item_t *item = cbor_new_definite_map(1);
    if (!item) {
        return 0;
    }

    // Set the boolean value based on the input data
    // Using the first byte of data to determine the boolean value
    bool value = data[0] % 2 == 0; // Even numbers are true, odd numbers are false
    cbor_item_t *key = cbor_build_uint8(0);
    cbor_item_t *val = cbor_build_bool(value);
    cbor_map_add(item, (struct cbor_pair){ .key = key, .value = val });

    // Call the function-under-test
    bool result = cbor_get_bool(val);

    // Clean up
    cbor_decref(&key);
    cbor_decref(&val);
    cbor_decref(&item);

    return 0;
}