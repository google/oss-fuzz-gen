#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>  // Include the Little CMS library header

// Define a fuzzing function that will be called by the fuzzer
int LLVMFuzzerTestOneInput_153(const uint8_t *data, size_t size) {
    // Ensure that the input size is sufficient to populate cmsCIELCh structure
    if (size < sizeof(cmsCIELCh)) {
        return 0;
    }

    // Initialize the input structures
    cmsCIELab lab;
    cmsCIELCh lch;

    // Populate the cmsCIELCh structure with data from the fuzzer input
    // Since cmsCIELCh contains 3 floats, we need to copy data into it
    // Ensure that the size is enough for 3 floats
    const float *float_data = (const float *)data;
    lch.L = float_data[0];
    lch.C = float_data[1];
    lch.h = float_data[2];

    // Call the function under test
    cmsLCh2Lab(&lab, &lch);

    return 0; // Return 0 to indicate successful execution
}