#include <cstdint>
#include <cbor.h>
#include <cstring> // For memcpy

extern "C" int LLVMFuzzerTestOneInput_82(const uint8_t *data, size_t size) {
    // Ensure that the size is at least 8 bytes to read a uint64_t
    if (size < sizeof(uint64_t)) {
        return 0;
    }

    // Read the first 8 bytes of data as a uint64_t
    uint64_t tag_value = 0;
    for (size_t i = 0; i < sizeof(uint64_t); ++i) {
        tag_value |= static_cast<uint64_t>(data[i]) << (8 * i);
    }

    // Create a CBOR tag item
    cbor_item_t *tag_item = cbor_new_tag(tag_value);

    // Create a CBOR integer item from the remaining data if any
    cbor_item_t *int_item = NULL;
    if (size > sizeof(uint64_t)) {
        int_item = cbor_build_uint8(data[sizeof(uint64_t)]);
    } else {
        int_item = cbor_build_uint8(0); // Default value if no extra data
    }

    // Add the integer item as the tagged item
    cbor_tag_set_item(tag_item, int_item);

    // Serialize the CBOR item to test more of the library
    unsigned char *buffer;
    size_t buffer_size;
    cbor_serialize_alloc(tag_item, &buffer, &buffer_size);

    // Clean up allocated memory
    free(buffer);
    cbor_decref(&tag_item);
    cbor_decref(&int_item);

    return 0;
}