#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_370(const uint8_t *data, size_t size) {
    // Ensure we have enough data to fill two cmsCIELab structures
    if (size < 6 * sizeof(cmsFloat64Number)) {
        return 0;
    }

    cmsCIELab lab1;
    cmsCIELab lab2;

    // Initialize the cmsCIELab structures with data from the input
    lab1.L = *((cmsFloat64Number*)(data));
    lab1.a = *((cmsFloat64Number*)(data + sizeof(cmsFloat64Number)));
    lab1.b = *((cmsFloat64Number*)(data + 2 * sizeof(cmsFloat64Number)));

    lab2.L = *((cmsFloat64Number*)(data + 3 * sizeof(cmsFloat64Number)));
    lab2.a = *((cmsFloat64Number*)(data + 4 * sizeof(cmsFloat64Number)));
    lab2.b = *((cmsFloat64Number*)(data + 5 * sizeof(cmsFloat64Number)));

    // Call the function-under-test
    cmsFloat64Number deltaE = cmsBFDdeltaE(&lab1, &lab2);

    // Use the result in some way to prevent optimization out
    volatile cmsFloat64Number result = deltaE;
    (void)result;

    return 0;
}