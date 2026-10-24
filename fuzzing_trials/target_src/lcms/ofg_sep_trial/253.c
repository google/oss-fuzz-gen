#include <stdint.h>
#include <stddef.h>
#include <string.h> // Include string.h for memcpy
#include <lcms2.h>

int LLVMFuzzerTestOneInput_253(const uint8_t *data, size_t size) {
    // Ensure there's enough data to populate the cmsCIELab structures and the two cmsFloat64Number values
    if (size < sizeof(cmsCIELab) * 2 + sizeof(cmsFloat64Number) * 2) {
        return 0;
    }

    // Initialize the cmsCIELab structures
    cmsCIELab Lab1, Lab2;

    // Copy data into the cmsCIELab structures
    const uint8_t *ptr = data;
    memcpy(&Lab1, ptr, sizeof(cmsCIELab));
    ptr += sizeof(cmsCIELab);
    memcpy(&Lab2, ptr, sizeof(cmsCIELab));
    ptr += sizeof(cmsCIELab);

    // Initialize the cmsFloat64Number values
    cmsFloat64Number weightL = *((cmsFloat64Number *)ptr);
    ptr += sizeof(cmsFloat64Number);
    cmsFloat64Number weightC = *((cmsFloat64Number *)ptr);

    // Call the function under test
    cmsFloat64Number deltaE = cmsCMCdeltaE(&Lab1, &Lab2, weightL, weightC);

    // Use the result to prevent the compiler from optimizing the call away
    volatile cmsFloat64Number result = deltaE;
    (void)result;

    return 0;
}