#include <cbor.h>
#include <stddef.h>
#include <stdint.h>

extern "C" int LLVMFuzzerTestOneInput_36(const uint8_t *data, size_t size) {
    // Ensure the size is non-zero to create a map with at least one element
    if (size == 0) {
        return 0;
    }

    // Use the size from the fuzzing input to create a definite map
    cbor_item_t *map = cbor_new_definite_map(size);

    // Perform operations on the map if necessary
    // For this fuzzing harness, we simply create and delete the map
    // to test the creation function for memory corruption issues.

    // Clean up the created map to avoid memory leaks
    cbor_decref(&map);

    return 0;
}