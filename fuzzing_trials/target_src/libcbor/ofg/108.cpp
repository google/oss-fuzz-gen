#include <cstdint>
#include <cbor.h>

extern "C" int LLVMFuzzerTestOneInput_108(const uint8_t *data, size_t size) {
    // Ensure there is at least one byte to read
    if (size < 1) {
        return 0;
    }

    // Use the first byte of the input data to call the function
    uint8_t control_value = data[0];

    // Call the function-under-test
    cbor_item_t* item = cbor_build_ctrl(control_value);

    // Clean up the cbor_item_t if it's not NULL
    if (item != NULL) {
        cbor_decref(&item);
    }

    return 0;
}