#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_186(const uint8_t *data, size_t size) {
    if (size < sizeof(cmsCIELab) * 2 + sizeof(cmsFloat64Number) * 3) {
        return 0;
    }

    // Initialize the cmsCIELab structures
    cmsCIELab Lab1, Lab2;
    cmsFloat64Number kL, kC, kH;

    // Copy data into the cmsCIELab structures and cmsFloat64Number variables
    size_t offset = 0;
    memcpy(&Lab1, data + offset, sizeof(cmsCIELab));
    offset += sizeof(cmsCIELab);
    memcpy(&Lab2, data + offset, sizeof(cmsCIELab));
    offset += sizeof(cmsCIELab);
    memcpy(&kL, data + offset, sizeof(cmsFloat64Number));
    offset += sizeof(cmsFloat64Number);
    memcpy(&kC, data + offset, sizeof(cmsFloat64Number));
    offset += sizeof(cmsFloat64Number);
    memcpy(&kH, data + offset, sizeof(cmsFloat64Number));

    // Call the function under test
    cmsFloat64Number deltaE = cmsCIE2000DeltaE(&Lab1, &Lab2, kL, kC, kH);

    // Use deltaE to avoid compiler optimizations
    volatile cmsFloat64Number avoid_optimization = deltaE;
    (void)avoid_optimization;

    return 0;
}