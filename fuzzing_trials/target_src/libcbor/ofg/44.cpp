extern "C" {
#include <cbor.h>
#include <stdlib.h>
#include <string.h>
}

extern "C" int LLVMFuzzerTestOneInput_44(const uint8_t *data, size_t size) {
    cbor_item_t *item = cbor_new_definite_bytestring();
    unsigned char *buffer = NULL;
    size_t buffer_size = 0;

    // Ensure the data is not empty
    if (size > 0) {
        // Copy data into the CBOR item
        cbor_bytestring_set_handle(item, (unsigned char *)malloc(size), size);
        memcpy(cbor_bytestring_handle(item), data, size);
    }

    // Call the function-under-test
    size_t serialized_size = cbor_serialize_alloc(item, &buffer, &buffer_size);

    // Clean up
    if (buffer != NULL) {
        free(buffer);
    }
    cbor_decref(&item);

    return 0;
}