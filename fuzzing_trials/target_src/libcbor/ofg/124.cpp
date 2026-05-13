#include <cbor.h>
#include <cstdint>
#include <cstdlib>

extern "C" {
    bool cbor_map_is_indefinite(const cbor_item_t *);
}

extern "C" int LLVMFuzzerTestOneInput_124(const uint8_t *data, size_t size) {
    // Ensure that the size is sufficient to create a cbor_item_t object
    if (size < 1) {
        return 0;
    }

    // Create a CBOR item
    cbor_item_t *item = cbor_new_definite_map(1);

    // Populate the CBOR item with data
    cbor_map_add(item, (struct cbor_pair) {
        .key = cbor_build_uint8(data[0]),
        .value = cbor_build_uint8(data[0])
    });

    // Call the function-under-test
    bool result = cbor_map_is_indefinite(item);

    // Clean up
    cbor_decref(&item);

    return 0;
}