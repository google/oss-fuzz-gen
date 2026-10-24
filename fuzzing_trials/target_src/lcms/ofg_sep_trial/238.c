#include <stdint.h>
#include <stdlib.h>
#include <string.h>  // Include for memcpy
#include <lcms2.h>

int LLVMFuzzerTestOneInput_238(const uint8_t *data, size_t size) {
    // Initialize variables
    cmsContext context = NULL;
    cmsCIExyY whitePoint;
    cmsHPROFILE profile;

    // Check if size is sufficient to extract data for cmsCIExyY
    if (size < sizeof(cmsCIExyY)) {
        return 0;
    }

    // Copy data into whitePoint, ensuring it is not NULL
    memcpy(&whitePoint, data, sizeof(cmsCIExyY));

    // Call the function-under-test
    profile = cmsCreateLab2ProfileTHR(context, &whitePoint);

    // Clean up the created profile if it is not NULL
    if (profile != NULL) {
        cmsCloseProfile(profile);
    }

    return 0;
}