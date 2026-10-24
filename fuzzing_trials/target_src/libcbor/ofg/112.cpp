#include <cstdint>
#include <cstring>
#include <cbor.h>

extern "C" int LLVMFuzzerTestOneInput_112(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient for a double
    if (size < sizeof(double)) {
        return 0;
    }

    // Extract a double value from the input data
    double value;
    memcpy(&value, data, sizeof(double));

    // Call the function-under-test
    cbor_item_t *item = cbor_build_float8(value);

    // Check if the item is successfully created
    if (item == NULL) {
        return 0;
    }

    // Further process the item to ensure code coverage
    // For example, serialize and deserialize the item
    unsigned char *buffer;
    size_t buffer_size;
    if (cbor_serialize_alloc(item, &buffer, &buffer_size) == 0) {
        // Deserialize to ensure the item can be properly handled
        struct cbor_load_result result;
        cbor_item_t *deserialized_item = cbor_load(buffer, buffer_size, &result);
        
        // Clean up the deserialized item
        if (deserialized_item != NULL) {
            cbor_decref(&deserialized_item);
        }

        // Free the allocated buffer
        free(buffer);
    }

    // Clean up the cbor_item_t
    cbor_decref(&item);

    return 0;
}