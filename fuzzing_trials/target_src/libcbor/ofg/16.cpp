#include <cstdint>
#include <cstddef>
#include <cbor.h>

extern "C" {
    size_t cbor_serialize_array(const cbor_item_t *item, unsigned char *buffer, size_t buffer_size);
}

extern "C" int LLVMFuzzerTestOneInput_16(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0; // Not enough data to proceed
    }

    // Initialize a CBOR array item with a size based on input data
    size_t array_size = data[0] % 10 + 1; // Ensure array size is reasonable
    cbor_item_t *array_item = cbor_new_definite_array(array_size);

    // Add CBOR integer items to the array based on input data
    for (size_t i = 0; i < array_size && i + 1 < size; ++i) {
        cbor_item_t *integer_item = cbor_build_uint8(data[i + 1]);
        cbor_array_push(array_item, integer_item);
        cbor_decref(&integer_item); // Decrease reference count after pushing
    }

    // Allocate a buffer for serialization
    size_t buffer_size = 256;
    unsigned char buffer[256];

    // Call the function-under-test
    cbor_serialize_array(array_item, buffer, buffer_size);

    // Clean up
    cbor_decref(&array_item);

    return 0;
}