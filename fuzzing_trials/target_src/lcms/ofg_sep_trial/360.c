#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_360(const uint8_t *data, size_t size) {
    if (size < 6 * sizeof(cmsFloat64Number)) {
        return 0; // Not enough data to create two cmsCIELab structures
    }

    cmsCIELab Lab1, Lab2;

    // Extract cmsFloat64Number values from the input data
    Lab1.L = *((cmsFloat64Number *)(data));
    Lab1.a = *((cmsFloat64Number *)(data + sizeof(cmsFloat64Number)));
    Lab1.b = *((cmsFloat64Number *)(data + 2 * sizeof(cmsFloat64Number)));

    Lab2.L = *((cmsFloat64Number *)(data + 3 * sizeof(cmsFloat64Number)));
    Lab2.a = *((cmsFloat64Number *)(data + 4 * sizeof(cmsFloat64Number)));
    Lab2.b = *((cmsFloat64Number *)(data + 5 * sizeof(cmsFloat64Number)));

    // Call the function under test
    cmsFloat64Number deltaE = cmsDeltaE(&Lab1, &Lab2);

    (void)deltaE; // Use deltaE to avoid unused variable warning

    return 0;
}