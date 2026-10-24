#include <cstdint>
#include <cstdlib>
#include <cbor.h>

extern "C" {
    size_t cbor_serialize_float_ctrl(const cbor_item_t *, unsigned char *, size_t);
}

extern "C" int LLVMFuzzerTestOneInput_175(const uint8_t *data, size_t size) {
    // Initialize a cbor_item_t object
    cbor_item_t *item = cbor_new_ctrl();
    if (item == NULL) {
        return 0;
    }

    // Initialize a buffer to serialize into
    unsigned char buffer[256]; // Adjust size as needed

    // Ensure the size is non-zero and within buffer limits
    size_t serialize_size = (size > 256) ? 256 : size;

    // Call the function-under-test
    cbor_serialize_float_ctrl(item, buffer, serialize_size);

    // Clean up
    cbor_decref(&item);

    return 0;
}