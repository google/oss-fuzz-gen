#include <stdint.h>
#include <stdlib.h>

extern "C" {
    #include <cbor.h>
}

extern "C" int LLVMFuzzerTestOneInput_57(const uint8_t *data, size_t size) {
    // Ensure there is at least one byte to read
    if (size < 1) {
        return 0;
    }

    // Use the entire data buffer to build a CBOR item
    cbor_item_t *item = cbor_build_bytestring(data, size);

    // Clean up the allocated cbor_item_t if it's not NULL
    if (item != NULL) {
        // Try to access some properties of the item
        cbor_type type = cbor_typeof(item);
        if (type == CBOR_TYPE_BYTESTRING) {
            // Access the bytestring content to ensure the item is valid and used
            unsigned char *bytes = cbor_bytestring_handle(item);
            size_t bytes_size = cbor_bytestring_length(item);

            // Further manipulate the bytes to increase code coverage
            for (size_t i = 0; i < bytes_size; ++i) {
                // Perform some operation with each byte
                if (bytes[i] + 1 != 0) {
                    // Perform some operation
                }
            }

            // Additional operations to increase code coverage
            // Attempt to convert the item to a different type and check the result
            cbor_item_t *converted_item = cbor_build_negint8(bytes_size % 256);
            if (converted_item != NULL) {
                // Check the type of the converted item
                cbor_type converted_type = cbor_typeof(converted_item);
                if (converted_type == CBOR_TYPE_NEGINT) {
                    // Access the negint8 value to ensure the item is valid and used
                    uint8_t neg_value = cbor_get_uint8(converted_item);
                    // Perform some operation with neg_value
                }
                cbor_decref(&converted_item);
            }

            // Try to encode the item to a CBOR buffer and decode it back
            unsigned char *buffer;
            size_t buffer_size;
            if (cbor_serialize_alloc(item, &buffer, &buffer_size)) {
                // Decode the serialized buffer back to a CBOR item
                struct cbor_load_result result;
                cbor_item_t *decoded_item = cbor_load(buffer, buffer_size, &result);
                if (decoded_item != NULL) {
                    // Check the type of the decoded item
                    cbor_type decoded_type = cbor_typeof(decoded_item);
                    if (decoded_type == CBOR_TYPE_BYTESTRING) {
                        // Perform operations on the decoded item
                    }
                    cbor_decref(&decoded_item);
                }
                free(buffer);
            }
        }
        
        cbor_decref(&item);
    }

    return 0;
}