#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_72(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    cmsCIEXYZ blackPoint;
    cmsHPROFILE profile = NULL;
    cmsUInt32Number intent = 0;
    cmsUInt32Number flags = 0;
    cmsBool result;

    // Ensure the data size is sufficient to create a profile
    if (size < sizeof(cmsHPROFILE)) {
        return 0;
    }

    // Create a dummy profile from the data
    profile = cmsOpenProfileFromMem(data, size);
    if (profile == NULL) {
        return 0;
    }

    // Call the function-under-test
    result = cmsDetectDestinationBlackPoint(&blackPoint, profile, intent, flags);

    // Clean up
    cmsCloseProfile(profile);

    return 0;
}