#include <cstdint>
#include <cstring>

extern "C" {
    #include <cbor.h>
}

extern "C" int LLVMFuzzerTestOneInput_88(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient to create a cbor_item_t
    if (size < sizeof(float)) {
        return 0;
    }

    // Initialize a cbor_item_t
    cbor_item_t *item = cbor_new_float8();
    if (item == nullptr) {
        return 0;
    }

    // Set the float value from the input data
    float value;
    memcpy(&value, data, sizeof(float));
    cbor_set_float8(item, value);

    // Call the function-under-test
    cbor_float_width width = cbor_float_get_width(item);

    // Additional operations to increase code coverage
    // Serialize the item to a buffer
    unsigned char *buffer;
    size_t buffer_size;
    if (cbor_serialize_alloc(item, &buffer, &buffer_size) == 1) {
        // Deserialize the buffer back to a cbor_item_t
        struct cbor_load_result result;
        cbor_item_t *deserialized_item = cbor_load(buffer, buffer_size, &result);

        // Ensure deserialization was successful
        if (deserialized_item != nullptr) {
            // Further operations can be added here if needed

            // Clean up the deserialized item
            cbor_decref(&deserialized_item);
        }

        // Free the allocated buffer
        free(buffer);
    }

    // Clean up
    cbor_decref(&item);

    return 0;
}