#include <cbor.h>
#include <stdint.h>
#include <stddef.h>

extern "C" {
    bool cbor_map_is_indefinite(const cbor_item_t *);
}

extern "C" int LLVMFuzzerTestOneInput_125(const uint8_t *data, size_t size) {
    // Check if the input size is sufficient to create a cbor_item_t
    if (size < 2) {
        return 0;
    }

    // Create a cbor_item_t as an indefinite map
    cbor_item_t *item = cbor_new_indefinite_map();
    if (item == NULL) {
        return 0;
    }

    // Set a dummy key-value pair to ensure the map is not empty
    cbor_item_t *key = cbor_build_uint8(data[0]);
    cbor_item_t *value = cbor_build_uint8(data[1]);
    cbor_map_add(item, (struct cbor_pair){ .key = key, .value = value });

    // Call the function-under-test
    bool result = cbor_map_is_indefinite(item);

    // Clean up
    cbor_decref(&item);
    cbor_decref(&key);
    cbor_decref(&value);

    return 0;
}