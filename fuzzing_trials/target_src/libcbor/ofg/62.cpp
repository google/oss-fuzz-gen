#include <cstdint>
#include <cbor.h>
#include <cbor/encoding.h>

extern "C" {
    #include <cbor/bytestrings.h>
    #include "/src/libcbor/src/cbor/data.h"
}

extern "C" int LLVMFuzzerTestOneInput_62(const uint8_t *data, size_t size) {
    // Ensure the data is not NULL and size is greater than zero
    if (data == nullptr || size == 0) {
        return 0;
    }

    // Attempt to decode the data as a CBOR item
    struct cbor_load_result result;
    cbor_item_t *item = cbor_load(data, size, &result);

    // If decoding was successful, perform operations on the CBOR item
    if (item != nullptr) {
        // Example operation: check if the item is a bytestring and get its content
        if (cbor_isa_bytestring(item)) {
            unsigned char *bytestring = cbor_bytestring_handle(item);
            size_t bytestring_size = cbor_bytestring_length(item);

            // Perform some operation on the bytestring
            // For example, just iterate over the bytes
            for (size_t i = 0; i < bytestring_size; ++i) {
                volatile unsigned char byte = bytestring[i];
                (void)byte; // Suppress unused variable warning
            }
        }

        // Clean up the cbor_item_t object
        cbor_decref(&item);
    }

    return 0;
}