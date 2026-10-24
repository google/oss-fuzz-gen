#include <stdint.h>
#include <stdlib.h>
#include <cbor.h>

extern "C" int LLVMFuzzerTestOneInput_27(const uint8_t *data, size_t size) {
    // Call the function-under-test
    cbor_item_t *item = cbor_new_float4();

    // Check if the item is not NULL
    if (item != NULL) {
        // Perform operations on the item if needed
        // For example, we can check the type of the item
        if (cbor_isa_float_ctrl(item)) {
            // If it's a float, we can set a value using the fuzz data
            if (size >= sizeof(float)) {
                float value;
                memcpy(&value, data, sizeof(float));
                cbor_set_float4(item, value);
            }
        }

        // Clean up and deallocate the item
        cbor_decref(&item);
    }

    return 0;
}