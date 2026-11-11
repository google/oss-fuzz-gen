#include <stdint.h>
#include <stddef.h>
#include <string.h>  // Include for memcpy
#include <lcms2.h>

int LLVMFuzzerTestOneInput_6(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient for a cmsCIExyY structure
    if (size < sizeof(cmsCIExyY)) {
        return 0;
    }

    // Create a cmsCIExyY structure from the input data
    cmsCIExyY whitePoint;
    const cmsCIExyY *wp = &whitePoint;

    // Copy data into the cmsCIExyY structure
    memcpy(&whitePoint, data, sizeof(cmsCIExyY));

    // Call the function-under-test
    cmsHPROFILE profile = cmsCreateLab2Profile(wp);

    // If a profile was created, release it
    if (profile != NULL) {
        cmsCloseProfile(profile);
    }

    return 0;
}