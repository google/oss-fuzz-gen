#include <cstdint>
#include <cstddef>
#include <cbor.h>

extern "C" int LLVMFuzzerTestOneInput_35(const uint8_t *data, size_t size) {
    // Ensure the size is not zero to avoid unnecessary calls
    if (size == 0) {
        return 0;
    }

    // Use the first byte of data to determine the size of the map
    size_t map_size = static_cast<size_t>(data[0]);

    // Call the function-under-test
    cbor_item_t *map = cbor_new_definite_map(map_size);

    // Clean up if map is successfully created
    if (map != nullptr) {
        cbor_decref(&map);
    }

    return 0;
}