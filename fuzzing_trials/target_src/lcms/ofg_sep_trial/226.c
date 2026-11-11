#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

// Define the LLVMFuzzerTestOneInput function
int LLVMFuzzerTestOneInput_226(const uint8_t *data, size_t size) {
    // Declare and initialize the variables needed for the function-under-test
    cmsUInt16Number encodedLab[3]; // Array to hold the encoded Lab values
    cmsCIELab lab;

    // Ensure the size is sufficient to extract values for cmsCIELab
    if (size < sizeof(cmsCIELab)) {
        return 0;
    }

    // Extract values from the data buffer to initialize cmsCIELab
    lab.L = ((const float *)data)[0];
    lab.a = ((const float *)data)[1];
    lab.b = ((const float *)data)[2];

    // Call the function-under-test
    cmsFloat2LabEncoded(encodedLab, &lab);

    return 0;
}