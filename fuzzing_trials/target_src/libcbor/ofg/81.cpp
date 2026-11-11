#include <cstdint>
#include <cstddef>
#include <cbor.h>

extern "C" int LLVMFuzzerTestOneInput_81(const uint8_t *data, size_t size) {
    // Attempt to parse the input data as a CBOR item
    struct cbor_load_result result;
    cbor_item_t *item = cbor_load(data, size, &result);

    // Ensure the item is not NULL and is a map
    if (item == NULL || !cbor_isa_map(item)) {
        return 0;
    }

    // Process the map, e.g., iterate over its elements
    size_t map_size = cbor_map_size(item);
    for (size_t i = 0; i < map_size; i++) {
        struct cbor_pair pair = cbor_map_handle(item)[i];
        // Do something with pair.key and pair.value
        // For example, simply access the data
        if (cbor_isa_uint(pair.key) && cbor_isa_uint(pair.value)) {
            uint64_t key_value = cbor_get_uint64(pair.key);
            uint64_t value_value = cbor_get_uint64(pair.value);
            // Use key_value and value_value for further processing
        }
    }

    // Clean up
    cbor_decref(&item);

    return 0;
}