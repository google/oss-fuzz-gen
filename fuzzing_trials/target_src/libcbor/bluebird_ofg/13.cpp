#include "cstdint"
#include "cbor.h"
#include "cstdlib"

extern "C" int LLVMFuzzerTestOneInput_13(const uint8_t *data, size_t size) {
    // Ensure there is at least one byte to read
    if (size < 1) {
        return 0;
    }

    // Extract the first byte to use as input for cbor_build_negint8
    uint8_t input_value = data[0];

    // Call the function-under-test
    cbor_item_t *result = cbor_build_negint8(input_value);

    // Check if the result is not NULL to ensure the function was invoked correctly
    if (result != NULL) {
        // Utilize the result to ensure code coverage
        cbor_type result_type = cbor_typeof(result);
        if (result_type == CBOR_TYPE_NEGINT) {
            // Optionally, perform more operations on the result to increase coverage
            unsigned char *buffer = NULL;
            size_t length = cbor_serialize_alloc(result, &buffer, &length);
            if (length > 0 && buffer != NULL) {
                cbor_serialize(result, buffer, length);
                free(buffer);
            }
        }

        // Clean up the result to avoid memory leaks
        cbor_decref(&result);
    }

    return 0;
}