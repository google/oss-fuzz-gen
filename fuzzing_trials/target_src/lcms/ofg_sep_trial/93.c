#include <inttypes.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_93(const uint8_t *data, size_t size) {
    cmsHPROFILE hProfile = NULL;

    // Ensure size is sufficient for a valid profile
    if (size < 128) {
        return 0;
    }

    // Create a profile from memory using the data
    hProfile = cmsOpenProfileFromMem(data, size);
    if (hProfile == NULL) {
        return 0;
    }

    // Call the function-under-test
    cmsBool result = cmsMD5computeID(hProfile);

    // Clean up
    cmsCloseProfile(hProfile);

    return 0;
}