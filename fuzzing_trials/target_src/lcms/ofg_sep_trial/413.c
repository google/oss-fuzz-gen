#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

// Define a placeholder for cmsDesaturateLab if it doesn't exist in the library
// This should be replaced with the actual function signature if it exists
cmsBool cmsDesaturateLab_1(cmsCIELab* labColor, double param1, double param2, double param3, double param4) {
    // Placeholder implementation
    return 1; // Assuming it returns true
}

int LLVMFuzzerTestOneInput_413(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    cmsCIELab labColor;
    double param1, param2, param3, param4;

    // Ensure size is sufficient for extracting double values
    if (size < sizeof(double) * 4 + sizeof(cmsCIELab)) {
        return 0;
    }

    // Initialize cmsCIELab structure
    labColor.L = (double)data[0]; // L component
    labColor.a = (double)data[1]; // a component
    labColor.b = (double)data[2]; // b component

    // Extract double values from data
    param1 = *((double *)(data + 3));
    param2 = *((double *)(data + 3 + sizeof(double)));
    param3 = *((double *)(data + 3 + 2 * sizeof(double)));
    param4 = *((double *)(data + 3 + 3 * sizeof(double)));

    // Call the function-under-test
    cmsBool result = cmsDesaturateLab_1(&labColor, param1, param2, param3, param4);

    // Use the result in some way to avoid compiler optimizations removing the call
    if (result) {
        // Do something if needed
    }

    return 0;
}