#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>
#include <string.h>  // Include for memcpy

int LLVMFuzzerTestOneInput_369(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient to fill two cmsCIELab structures
    if (size < 2 * sizeof(cmsCIELab)) {
        return 0;
    }

    // Initialize two cmsCIELab structures
    cmsCIELab lab1;
    cmsCIELab lab2;

    // Copy data into the cmsCIELab structures
    // Use memcpy to correctly interpret the data as floats
    memcpy(&lab1, data, sizeof(cmsCIELab));
    memcpy(&lab2, data + sizeof(cmsCIELab), sizeof(cmsCIELab));

    // Call the function-under-test
    cmsFloat64Number deltaE = cmsBFDdeltaE(&lab1, &lab2);

    // Use deltaE in some way to avoid compiler optimizations
    volatile cmsFloat64Number result = deltaE;
    (void)result;

    return 0;
}