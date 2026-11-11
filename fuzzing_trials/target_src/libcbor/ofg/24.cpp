#include <cstdint>
#include <cbor.h>

extern "C" {
    #include <cbor/floats_ctrls.h>
    #include "/src/libcbor/src/cbor/data.h" // Include necessary CBOR data header
    #include "/src/libcbor/src/cbor/floats_ctrls.h" // Include the header file for function declarations

    bool cbor_float_ctrl_is_ctrl(const cbor_item_t *);
}

extern "C" int LLVMFuzzerTestOneInput_24(const uint8_t *data, size_t size) {
    // Ensure the data size is appropriate for creating a CBOR item
    if (size < 1) {
        return 0;
    }

    // Create a CBOR item based on the input data
    cbor_item_t *item = cbor_new_ctrl();

    // Use the input data to set different control values
    for (size_t i = 0; i < size; ++i) {
        cbor_set_ctrl(item, data[i]);

        // Call the function-under-test
        bool result = cbor_float_ctrl_is_ctrl(item);

        // Use the result to prevent compiler optimization
        if (result) {
            // Log or assert to utilize the result
            volatile bool prevent_optimization = result;
            (void)prevent_optimization;
        }
    }

    // Clean up
    cbor_decref(&item);

    return 0;
}