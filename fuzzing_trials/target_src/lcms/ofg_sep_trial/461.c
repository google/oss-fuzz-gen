#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_461(const uint8_t *data, size_t size) {
    cmsHPROFILE hProfile;
    struct tm creationDateTime;

    // Initialize a memory profile from the data
    if (size == 0) return 0;
    hProfile = cmsOpenProfileFromMem((const void*)data, (cmsUInt32Number)size);
    if (hProfile == NULL) return 0;

    // Call the function-under-test
    cmsBool result = cmsGetHeaderCreationDateTime(hProfile, &creationDateTime);

    // Clean up
    cmsCloseProfile(hProfile);

    return 0;
}