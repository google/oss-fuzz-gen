#include <cbor.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

extern "C" int LLVMFuzzerTestOneInput_70(const uint8_t *data, size_t size) {
    // Ensure that the data size is sufficient for creating a map
    if (size < 2) {
        return 0;
    }

    // Initialize the CBOR map item
    cbor_item_t *map = cbor_new_definite_map(1); // Create a map with at least one pair

    // Create a key and value for the map
    cbor_item_t *key = cbor_build_uint8(data[0]);
    cbor_item_t *value = cbor_build_uint8(data[1]);

    // Add the key-value pair to the map
    struct cbor_pair pair;
    pair.key = key;
    pair.value = value;
    cbor_map_add(map, pair);

    // Allocate a buffer for serialization
    size_t buffer_size = 128; // Arbitrary buffer size
    unsigned char *buffer = (unsigned char *)malloc(buffer_size);

    // Call the function-under-test
    if (buffer != NULL) {
        size_t bytes_serialized = cbor_serialize_map(map, buffer, buffer_size);
        
        // Use the serialized data in some way (optional, for debugging)
        (void)bytes_serialized; // Suppress unused variable warning
    }

    // Clean up
    cbor_decref(&key);
    cbor_decref(&value);
    cbor_decref(&map);
    free(buffer);

    return 0;
}