#include <stdint.h>
#include <stdlib.h>

extern "C" {
    // Include the necessary headers for the CBOR library
    #include <cbor.h>
}

// Fuzzing harness for the function-under-test
extern "C" int LLVMFuzzerTestOneInput_11(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient to create a CBOR item
    if (size < 1) {
        return 0;
    }

    // Create a CBOR item from the input data
    struct cbor_load_result result;
    cbor_item_t *item = cbor_load(data, size, &result);

    // Check if the item was created successfully
    if (item == NULL) {
        return 0;
    }

    // Ensure that the item is of the correct type for cbor_set_ctrl
    if (cbor_isa_float_ctrl(item)) { // Assuming cbor_isa_float_ctrl is the correct function for control types
        // Extract a uint8_t value from the input data
        uint8_t ctrl_value = data[0];

        // Call the function-under-test
        cbor_set_ctrl(item, ctrl_value);
    }

    // Clean up the CBOR item
    cbor_decref(&item);

    return 0;
}