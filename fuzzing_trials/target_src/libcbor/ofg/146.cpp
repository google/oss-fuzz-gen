#include <cbor.h>
#include <stdint.h>
#include <stddef.h>

extern "C" int LLVMFuzzerTestOneInput_146(const uint8_t *data, size_t size) {
    // Declare and initialize the cbor_item_t pointer
    cbor_item_t *map = cbor_new_definite_map(1);

    // Ensure there's enough data to create a cbor_pair
    if (size < 2) {
        cbor_decref(&map);
        return 0;
    }

    // Create a cbor_pair
    struct cbor_pair pair;
    pair.key = cbor_build_uint8(data[0]); // Using first byte as key
    pair.value = cbor_build_uint8(data[1]); // Using second byte as value

    // Call the function-under-test
    cbor_map_add(map, pair);

    // Clean up
    cbor_decref(&pair.key);
    cbor_decref(&pair.value);
    cbor_decref(&map);

    return 0;
}