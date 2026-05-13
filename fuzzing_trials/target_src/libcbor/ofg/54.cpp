#include <cstdint>
#include <cstring> // Include for memcpy
#include <cbor.h>

extern "C" int LLVMFuzzerTestOneInput_54(const uint8_t *data, size_t size) {
    // Ensure that the size is sufficient to extract a float value
    if (size < sizeof(float)) {
        return 0;
    }

    // Extract a float value from the input data
    float value;
    memcpy(&value, data, sizeof(float));

    // Call the function-under-test
    cbor_item_t *item = cbor_build_float2(value);

    // Additional operations to increase code coverage
    if (item != nullptr) {
        // Attempt to serialize the CBOR item
        unsigned char *buffer;
        size_t buffer_size;
        if (cbor_serialize_alloc(item, &buffer, &buffer_size)) {
            // Successfully serialized, now try to deserialize
            struct cbor_load_result result;
            cbor_item_t *deserialized_item = cbor_load(buffer, buffer_size, &result);
            if (deserialized_item != nullptr) {
                cbor_decref(&deserialized_item);
            }
            free(buffer);
        }
        cbor_decref(&item);
    }

    return 0;
}