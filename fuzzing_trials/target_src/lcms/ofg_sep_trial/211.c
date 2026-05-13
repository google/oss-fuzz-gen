#include <stdint.h>
#include <stddef.h>
#include <string.h>  // Include this for memcpy
#include <lcms2.h>

int LLVMFuzzerTestOneInput_211(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for the cmsCIELab structure
    if (size < sizeof(cmsCIELab)) {
        return 0;
    }

    // Initialize the cmsCIELab structure from the input data
    cmsCIELab lab;
    const cmsCIELab *labPtr = &lab;
    memcpy(&lab, data, sizeof(cmsCIELab));

    // Initialize the cmsUInt16Number array
    cmsUInt16Number encodedLab[3] = {0, 0, 0};

    // Call the function-under-test
    cmsFloat2LabEncodedV2(encodedLab, labPtr);

    return 0;
}