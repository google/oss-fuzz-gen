#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_460(const uint8_t *data, size_t size) {
    cmsHPROFILE profile;
    struct tm creationTime;
    cmsBool result;

    // Initialize LCMS memory management
    cmsSetLogErrorHandler(NULL);

    // Create a profile from the input data
    profile = cmsOpenProfileFromMem(data, size);
    if (profile == NULL) {
        return 0; // Return if the profile could not be created
    }

    // Call the function-under-test
    result = cmsGetHeaderCreationDateTime(profile, &creationTime);

    // Close the profile
    cmsCloseProfile(profile);

    return 0;
}