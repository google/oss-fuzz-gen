#include <cbor.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput_145(const uint8_t *data, size_t size) {
    // Initialize the cbor_item_t object
    cbor_item_t *map = cbor_new_definite_map(1);  // Create a map with at least 1 pair

    // Ensure we have enough data to form a key-value pair
    if (size < 2) {
        cbor_decref(&map);
        return 0;
    }

    // Create a cbor_pair
    struct cbor_pair pair;
    
    // Initialize key and value from the data
    pair.key = cbor_build_uint8(data[0]);  // Use the first byte as the key
    pair.value = cbor_build_uint8(data[1]);  // Use the second byte as the value

    // Call the function-under-test
    cbor_map_add(map, pair);

    // Clean up
    cbor_decref(&pair.key);
    cbor_decref(&pair.value);
    cbor_decref(&map);

    return 0;
}