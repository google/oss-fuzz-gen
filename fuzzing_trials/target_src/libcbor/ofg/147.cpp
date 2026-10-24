#include <cbor.h>
#include <cstddef>
#include <cstdint>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput_147(const uint8_t *data, size_t size) {
    // Create a cbor_item_t object
    cbor_item_t *item = cbor_new_definite_string();
    if (item == NULL) {
        return 0;
    }

    // Ensure the data is not null and size is greater than zero
    if (data != NULL && size > 0) {
        // Allocate memory for the string and copy the data into it
        unsigned char *str_data = (unsigned char *)malloc(size);
        if (str_data == NULL) {
            cbor_decref(&item);
            return 0;
        }
        memcpy(str_data, data, size);

        // Set the string data in the cbor_item_t
        cbor_string_set_handle(item, str_data, size);

        // Allocate a buffer for serialization
        size_t buffer_size = size * 2; // Assuming the buffer size is twice the input size
        unsigned char *buffer = (unsigned char *)malloc(buffer_size);
        if (buffer == NULL) {
            free(str_data);
            cbor_decref(&item);
            return 0;
        }

        // Call the function-under-test
        cbor_serialize_string(item, buffer, buffer_size);

        // Clean up
        free(buffer);
    }

    cbor_decref(&item);
    return 0;
}