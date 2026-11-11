#include <cstdint>
#include <cstring>
#include <cbor.h>
#include <cmath> // Include cmath for isnan function

// Ensure the function-under-test is wrapped in extern "C" for C++ compatibility
extern "C" {
    cbor_item_t * cbor_build_float2(float);
    void cbor_decref(cbor_item_t **item);
}

extern "C" int LLVMFuzzerTestOneInput_55(const uint8_t *data, size_t size) {
    // Declare and initialize the float variable
    float input_float = 0.0f;

    // Check if the size is sufficient to read a float value
    if (size >= sizeof(float)) {
        // Copy the data into the float variable
        std::memcpy(&input_float, data, sizeof(float));
    } else {
        // If not enough data, return early to avoid ineffective fuzzing
        return 0;
    }

    // Check if the input_float is a valid float (not NaN)
    if (!std::isnan(input_float)) {
        // Call the function-under-test with the float input
        cbor_item_t *result = cbor_build_float2(input_float);

        // Check if result is not null before attempting to use it
        if (result != nullptr) {
            // Perform operations on the result to ensure code coverage
            // For example, access some properties or methods of cbor_item_t
            // Example: cbor_serialize(result, buffer, buffer_size);

            // Clean up if necessary (assuming cbor_item_t is dynamically allocated)
            cbor_decref(&result);
        }
    }

    return 0;
}