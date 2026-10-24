#include <stdint.h>
#include <stddef.h>
#include <cbor.h>

extern "C" int LLVMFuzzerTestOneInput_12(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0; // No input data to process
    }

    // Call the function-under-test
    cbor_item_t *item = cbor_new_int8();

    // If the function returns a non-null pointer, perform some operations
    if (item != NULL) {
        // Use the input data to set a value in the cbor_item_t object
        // Assuming the input data is large enough to read an int8_t
        int8_t value = static_cast<int8_t>(data[0]);
        cbor_set_uint8(item, value);

        // Serialize the cbor_item_t object to test serialization functionality
        unsigned char *buffer;
        size_t buffer_size;
        buffer_size = cbor_serialize_alloc(item, &buffer, &buffer_size);

        // Free the buffer after serialization
        if (buffer_size > 0) {
            free(buffer);
        }

        // Clean up the cbor_item_t object
        cbor_decref(&item);
    }

    return 0;
}