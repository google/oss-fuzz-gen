#include "cstdint"
#include "cstdlib"
#include <cstring> // Include for memcpy

extern "C" {
    #include "cbor.h"
}

extern "C" int LLVMFuzzerTestOneInput_7(const uint8_t *data, size_t size) {
    // Check if the size is sufficient to interpret as a double
    if (size >= sizeof(double)) {
        // Declare and initialize a cbor_item_t pointer
        cbor_item_t *item = cbor_new_float8();

        // Copy the data into a double variable
        double value;
        memcpy(&value, data, sizeof(double));

        // Set the value to the cbor_item_t

        // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 1 of cbor_set_float8
        cbor_set_float8(item, -1);
        // End mutation: Producer.REPLACE_ARG_MUTATOR



        // Call the function-under-test
        double result = cbor_float_get_float(item);

        // Perform an operation with the result to ensure code coverage
        if (result != value) {
            // Log or handle the discrepancy
        }

        // Decrease the reference count and free the item
        cbor_decref(&item);
    }

    // Additional code to ensure the function is meaningfully exercised
    if (size > sizeof(double)) {
        // Use remaining data to create a more complex CBOR item
        struct cbor_load_result load_result;
        cbor_item_t *complex_item = cbor_load(data, size, &load_result);

        if (complex_item != nullptr) {
            // Perform operations on the complex item
            if (cbor_is_float(complex_item)) {
                double complex_result = cbor_float_get_float(complex_item);
                // Perform an operation with the complex result
                if (complex_result != 0) {
                    // Log or handle the discrepancy
                }
            }
            cbor_decref(&complex_item);
        }
    }

    return 0;
}