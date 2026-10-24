#include <stdint.h>
#include <stddef.h>
#include <cbor.h>

extern "C" int LLVMFuzzerTestOneInput_178(const uint8_t *data, size_t size) {
    // Call the function-under-test
    cbor_item_t *item = cbor_new_int16();

    // Ensure the function call was successful and item is not NULL
    if (item != NULL) {
        // Perform operations on the item if needed
        // For example, you can set the value of the item using the provided data
        if (size >= 2) {
            // Assuming the data is at least 2 bytes to form a 16-bit integer
            int16_t value = (int16_t)((data[0] << 8) | data[1]);
            cbor_set_uint16(item, value);
        }

        // Clean up and free the allocated cbor_item_t
        cbor_decref(&item);
    }

    return 0;
}