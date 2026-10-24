#include <stdint.h>
#include <stddef.h>
#include <cbor.h>
#include <string.h> // Include string.h for memcpy
#include <cmath> // Include cmath for INFINITY and NAN
#include <cfloat> // Include cfloat for DBL_MAX and DBL_MIN

// Include the necessary C headers and wrap them in extern "C" to ensure compatibility with C++.
extern "C" {
    #include <cbor/floats_ctrls.h> // Include the correct header for the cbor functions

    // Function prototype from the project-under-test.
    cbor_item_t * cbor_new_float8();
    void cbor_decref(cbor_item_t **item);
    void cbor_set_float8(cbor_item_t *item, double value); // Correct the function signature to match the header
}

extern "C" int LLVMFuzzerTestOneInput_46(const uint8_t *data, size_t size) {
    // Check if the input data size is sufficient for the operation.
    if (size < sizeof(float)) {
        return 0; // Not enough data to create a float8, return early.
    }

    // Call the function-under-test.
    cbor_item_t *item = cbor_new_float8();

    // Perform operations with the item if it is successfully created.
    if (item != NULL) {
        // Use the input data to set a float value in the cbor item.
        float value;
        memcpy(&value, data, sizeof(float)); // Copy data to a float variable
        cbor_set_float8(item, static_cast<double>(value)); // Cast float to double for the function call

        // Additional operations to increase coverage
        // Attempt to manipulate the CBOR item to explore more code paths
        double test_values[] = {0.0, -0.0, 1.0, -1.0, 3.14159, -3.14159, 1e-10, -1e-10, 1e10, -1e10};
        for (int i = 0; i < sizeof(test_values)/sizeof(test_values[0]); ++i) {
            cbor_set_float8(item, test_values[i]);
        }

        // Introduce additional logic to explore more code paths
        // Attempt to set the float8 to various edge-case values
        cbor_set_float8(item, INFINITY);
        cbor_set_float8(item, -INFINITY);
        cbor_set_float8(item, NAN);

        // Additional logic to test the limits of the function
        // Try setting the float8 to the largest and smallest possible double values
        cbor_set_float8(item, DBL_MAX);
        cbor_set_float8(item, -DBL_MAX);
        cbor_set_float8(item, DBL_MIN);
        cbor_set_float8(item, -DBL_MIN);

        // Free the allocated cbor_item_t to prevent memory leaks.
        cbor_decref(&item);
    }

    return 0;
}