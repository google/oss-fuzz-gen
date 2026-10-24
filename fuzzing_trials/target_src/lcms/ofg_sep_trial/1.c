#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_1(const uint8_t *data, size_t size) {
    if (size < 6 * sizeof(cmsFloat64Number)) {
        return 0; // Not enough data to fill two cmsCIELab structs
    }

    cmsCIELab Lab1;
    cmsCIELab Lab2;

    // Initialize cmsCIELab structures with data
    Lab1.L = *(cmsFloat64Number *)(data);
    Lab1.a = *(cmsFloat64Number *)(data + sizeof(cmsFloat64Number));
    Lab1.b = *(cmsFloat64Number *)(data + 2 * sizeof(cmsFloat64Number));

    Lab2.L = *(cmsFloat64Number *)(data + 3 * sizeof(cmsFloat64Number));
    Lab2.a = *(cmsFloat64Number *)(data + 4 * sizeof(cmsFloat64Number));
    Lab2.b = *(cmsFloat64Number *)(data + 5 * sizeof(cmsFloat64Number));

    // Call the function-under-test
    cmsFloat64Number deltaE = cmsCIE94DeltaE(&Lab1, &Lab2);

    // Use the result to avoid any compiler optimizations
    volatile cmsFloat64Number result = deltaE;
    (void)result;

    return 0;
}