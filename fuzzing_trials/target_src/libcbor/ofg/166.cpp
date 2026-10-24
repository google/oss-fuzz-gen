#include <cstdint>
#include <cstdlib>
#include <cbor.h>

extern "C" int LLVMFuzzerTestOneInput_166(const uint8_t *data, size_t size) {
    // Initialize a CBOR item
    cbor_item_t *item = cbor_new_int8();
    if (item == NULL) {
        return 0;
    }

    // Set the CBOR item value from the input data
    if (size > 0) {
        cbor_set_uint8(item, data[0]);
    } else {
        cbor_set_uint8(item, 0); // Default value if no data
    }

    // Allocate a buffer for serialization
    size_t buffer_size = 10; // Arbitrary buffer size for demonstration
    unsigned char *buffer = (unsigned char *)malloc(buffer_size);
    if (buffer == NULL) {
        cbor_decref(&item);
        return 0;
    }

    // Call the function-under-test
    size_t serialized_size = cbor_serialize_uint(item, buffer, buffer_size);

    // Clean up
    free(buffer);
    cbor_decref(&item);

    return 0;
}