extern "C" {
    #include <cbor.h>
}

extern "C" int LLVMFuzzerTestOneInput_6(const uint8_t *data, size_t size) {
    // Ensure that size is at least 1 to extract a boolean value
    if (size < 1) {
        return 0;
    }

    // Extract a boolean value from the data
    bool value = (data[0] % 2 == 0); // Use the first byte to determine true/false

    // Call the function-under-test
    cbor_item_t *item = cbor_build_bool(value);

    // Additional processing to increase code coverage
    if (item != NULL) {
        // Serialize the item to a buffer
        unsigned char *buffer;
        size_t buffer_size;
        buffer_size = cbor_serialize_alloc(item, &buffer, &buffer_size);

        // Deserialize the buffer back to a cbor_item_t
        struct cbor_load_result result;
        cbor_item_t *deserialized_item = cbor_load(buffer, buffer_size, &result);

        // Clean up the created cbor_item_t and buffer
        cbor_decref(&item);
        free(buffer);

        if (deserialized_item != NULL) {
            cbor_decref(&deserialized_item);
        }
    }

    return 0;
}