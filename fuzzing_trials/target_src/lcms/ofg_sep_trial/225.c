#include <stdint.h>
#include <stddef.h>
#include <string.h>  // Include this for memcpy
#include <lcms2.h>

int LLVMFuzzerTestOneInput_225(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient to construct a cmsCIELab structure
    if (size < sizeof(cmsCIELab)) {
        return 0;
    }

    // Initialize cmsCIELab structure from input data
    cmsCIELab lab;
    const cmsCIELab *labPtr = &lab;
    // Copy data into the cmsCIELab structure
    memcpy(&lab, data, sizeof(cmsCIELab));

    // Initialize cmsUInt16Number array
    cmsUInt16Number encodedLab[3] = {0, 0, 0};

    // Call the function-under-test
    cmsFloat2LabEncoded(encodedLab, labPtr);

    return 0;
}