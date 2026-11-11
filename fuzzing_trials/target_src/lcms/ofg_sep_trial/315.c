#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_315(const uint8_t *data, size_t size) {
    // Initialize a cmsHPROFILE
    cmsHPROFILE hProfile = cmsCreate_sRGBProfile();

    // Allocate memory for cmsUInt8Number array
    cmsUInt8Number *profileID = (cmsUInt8Number *)malloc(16 * sizeof(cmsUInt8Number));
    if (profileID == NULL) {
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Ensure that the input size is at least 16 bytes to fill the profileID
    if (size >= 16) {
        memcpy(profileID, data, 16);
    } else {
        // If not enough data, fill with zeros
        memset(profileID, 0, 16);
    }

    // Call the function-under-test
    cmsSetHeaderProfileID(hProfile, profileID);

    // Clean up
    free(profileID);
    cmsCloseProfile(hProfile);

    return 0;
}