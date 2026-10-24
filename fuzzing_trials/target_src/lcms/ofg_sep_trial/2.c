#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_2(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for two cmsCIELab structures
    if (size < 2 * sizeof(cmsCIELab)) {
        return 0;
    }

    // Create two cmsCIELab structures from the input data
    cmsCIELab lab1;
    cmsCIELab lab2;

    // Copy data into the first cmsCIELab structure
    const uint8_t *ptr = data;
    lab1.L = *((cmsFloat64Number*)ptr);
    ptr += sizeof(cmsFloat64Number);
    lab1.a = *((cmsFloat64Number*)ptr);
    ptr += sizeof(cmsFloat64Number);
    lab1.b = *((cmsFloat64Number*)ptr);
    ptr += sizeof(cmsFloat64Number);

    // Copy data into the second cmsCIELab structure
    lab2.L = *((cmsFloat64Number*)ptr);
    ptr += sizeof(cmsFloat64Number);
    lab2.a = *((cmsFloat64Number*)ptr);
    ptr += sizeof(cmsFloat64Number);
    lab2.b = *((cmsFloat64Number*)ptr);

    // Call the function under test
    cmsFloat64Number deltaE = cmsCIE94DeltaE(&lab1, &lab2);

    // Use deltaE in some way to avoid compiler optimizations removing the call
    // (In a real fuzzing scenario, this would not be necessary)
    (void)deltaE;

    return 0;
}