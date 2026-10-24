#include <stdint.h>
#include <cbor.h>

extern "C" int LLVMFuzzerTestOneInput_40(const uint8_t *data, size_t size) {
    // Ensure the data size is non-zero to create a valid CBOR item
    if (size == 0) {
        return 0;
    }

    // Create a new CBOR item
    cbor_item_t *item = cbor_new_definite_map(size);

    // Populate the CBOR map with dummy key-value pairs
    for (size_t i = 0; i < size; ++i) {
        cbor_item_t *key = cbor_build_uint8(data[i]);
        cbor_item_t *value = cbor_build_uint8(data[size - i - 1]);
        cbor_map_add(item, (struct cbor_pair) {
            .key = key,
            .value = value
        });
    }

    // Call the function-under-test
    bool result = cbor_map_is_definite(item);

    // Clean up the CBOR item
    cbor_decref(&item);

    return 0;
}