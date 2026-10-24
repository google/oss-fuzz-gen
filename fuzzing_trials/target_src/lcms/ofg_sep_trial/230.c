#include <stdint.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_230(const uint8_t *data, size_t size) {
    // Ensure there is enough data to read for cmsCIExyY structure
    if (size < 3 * sizeof(double)) {
        return 0;
    }

    // Create a cmsCIExyY structure and populate it with data
    cmsCIExyY ciexyY;
    ciexyY.x = *((double *)data);
    ciexyY.y = *((double *)(data + sizeof(double)));
    ciexyY.Y = *((double *)(data + 2 * sizeof(double)));

    // Call the function-under-test
    cmsHPROFILE profile = cmsCreateLab4Profile(&ciexyY);

    // Clean up the created profile
    if (profile != NULL) {
        cmsCloseProfile(profile);
    }

    return 0;
}