#include <cstdint>
#include <stdlib.h>
#include <string.h> // Include for memcpy

extern "C" {
    #include <cbor.h>
}

extern "C" int LLVMFuzzerTestOneInput_119(const uint8_t *data, size_t size) {
    // Attempt to parse the input data as a CBOR item
    struct cbor_load_result result;
    cbor_item_t *item = cbor_load(data, size, &result);

    // Check if the item was successfully parsed
    if (item == NULL) {
        return 0;
    }

    // Depending on the type of item, perform different operations
    if (cbor_isa_float_ctrl(item)) {
        // If the item is a float, retrieve its value
        double value = cbor_float_get_float(item);
        // Use the value in some way
        (void)value; // Suppress unused variable warning
    }

    // Clean up
    cbor_decref(&item);

    return 0;
}