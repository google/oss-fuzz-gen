#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" {
    #include <cbor.h>
    #include <cbor/bytestrings.h>

    size_t cbor_serialize(const cbor_item_t *, unsigned char *, size_t);
}

extern "C" int LLVMFuzzerTestOneInput_48(const uint8_t *data, size_t size) {
    // Ensure we have enough data to work with
    if (size < 1) {
        return 0;
    }

    // Create a CBOR item from the input data
    cbor_item_t *item = cbor_new_definite_bytestring();
    if (item == NULL) {
        return 0;
    }

    // Set the content of the bytestring
    unsigned char *data_copy = (unsigned char *)malloc(size);
    if (data_copy == NULL) {
        cbor_decref(&item);
        return 0;
    }
    memcpy(data_copy, data, size);
    cbor_bytestring_set_handle(item, data_copy, size);

    // Allocate a buffer for serialization
    size_t buffer_size = size * 2; // Arbitrary buffer size larger than input
    unsigned char *buffer = (unsigned char *)malloc(buffer_size);
    if (buffer == NULL) {
        cbor_bytestring_set_handle(item, NULL, 0); // Detach the handle before decref
        cbor_decref(&item);
        return 0;
    }

    // Call the function-under-test
    size_t serialized_size = cbor_serialize(item, buffer, buffer_size);

    // Check if serialization was successful
    if (serialized_size > buffer_size) {
        // Handle serialization error
        free(buffer);
        cbor_bytestring_set_handle(item, NULL, 0); // Detach the handle before decref
        cbor_decref(&item);
        return 0;
    }

    // Clean up
    free(buffer);
    cbor_bytestring_set_handle(item, NULL, 0); // Detach the handle before decref
    cbor_decref(&item);

    return 0;
}