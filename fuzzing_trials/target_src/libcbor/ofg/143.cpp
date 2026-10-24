#include <stdint.h>
#include <stddef.h>
#include <cbor.h>

extern "C" int LLVMFuzzerTestOneInput_143(const uint8_t *data, size_t size) {
    if (size < sizeof(float)) {
        return 0; // Not enough data to form a float
    }

    // Interpret the first few bytes of data as a float
    float value;
    memcpy(&value, data, sizeof(float));

    // Create a new CBOR float item with the interpreted value
    cbor_item_t *float_item = cbor_build_float8(value);

    // Perform operations on the CBOR item
    if (float_item != NULL) {
        // For example, get the float value back from the CBOR item
        double retrieved_value = cbor_float_get_float(float_item);

        // Ensure the value is used in some way to prevent optimization out
        if (retrieved_value != value) {
            // This is unlikely, but we need to ensure the value is used
            return 1;
        }

        // Decrement the reference count and free the item
        cbor_decref(&float_item);
    }

    return 0;
}