#include <stdint.h>
#include <stddef.h>
#include <cbor.h>
#include <stdlib.h>

extern "C" int LLVMFuzzerTestOneInput_130(const uint8_t *data, size_t size) {
    // Parse the input data as a CBOR item
    struct cbor_load_result result;
    cbor_item_t *item = cbor_load(data, size, &result);

    // Check if the item was successfully parsed
    if (item != NULL) {
        // Optionally perform operations on item to increase coverage
        // For example, accessing item properties or calling other CBOR functions
        if (cbor_isa_uint(item)) {
            // Example operation: retrieve the integer value
            uint64_t int_value = cbor_get_int(item);
        } else if (cbor_isa_negint(item)) {
            // Example operation: retrieve the negative integer value
            uint64_t negint_value = cbor_get_int(item);
        } else if (cbor_isa_bytestring(item)) {
            // Example operation: retrieve the bytestring length
            size_t bytestring_length = cbor_bytestring_length(item);
        } else if (cbor_isa_string(item)) {
            // Example operation: retrieve the string length
            size_t string_length = cbor_string_length(item);
        } else if (cbor_isa_array(item)) {
            // Example operation: retrieve the array size
            size_t array_size = cbor_array_size(item);
        } else if (cbor_isa_map(item)) {
            // Example operation: retrieve the map size
            size_t map_size = cbor_map_size(item);
        }
        
        // Decrement the reference count to free the item
        cbor_decref(&item);
    }

    return 0;
}