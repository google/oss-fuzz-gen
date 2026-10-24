extern "C" {
    #include <stdint.h>
    #include <stdlib.h>
    #include <string.h> // Include string.h for memcpy
    #include <cbor.h>
}

#include <cmath> // Include cmath for isnan and isinf

extern "C" int LLVMFuzzerTestOneInput_120(const uint8_t *data, size_t size) {
    if (size < sizeof(float)) {
        return 0; // Not enough data to create a float
    }

    // Copy the first 4 bytes of data to a float variable
    float input_float;
    memcpy(&input_float, data, sizeof(float));

    // Call the function-under-test
    cbor_item_t *result = cbor_build_float4(input_float);

    // Ensure that the result is not NULL before freeing it
    if (result != NULL) {
        // Perform operations on the result to increase code coverage
        if (cbor_isa_float_ctrl(result)) {
            // Access the float value to ensure the function is being exercised
            float extracted_float = cbor_float_get_float(result);

            // Additional checks to exercise more code paths
            if (extracted_float != input_float) {
                // Handle unexpected cases
                // For example, log or assert (in real fuzzing, this would be used to detect bugs)
            }

            // Check for special float values
            if (std::isnan(extracted_float) || std::isinf(extracted_float)) {
                // Handle special float cases
            }
        }

        // Additional operations to increase code coverage
        // Example: Check the type of the result
        if (cbor_typeof(result) == CBOR_TYPE_FLOAT_CTRL) {
            // Perform some operation based on the type
            // For example, retrieve the float value and perform calculations
            float value = cbor_float_get_float(result);
            volatile float test_calculation = value * 2.0f; // Dummy operation to exercise the code path
        }

        // Decrement the reference count to free the item
        cbor_decref(&result);
    }

    // Additional operations to increase code coverage
    // Attempt to parse the data as a CBOR item to exercise more paths
    struct cbor_load_result load_result;
    cbor_item_t *parsed_item = cbor_load(data, size, &load_result);
    if (parsed_item != NULL) {
        // Perform operations on the parsed item
        cbor_decref(&parsed_item);
    }

    return 0;
}