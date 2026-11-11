#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_327(const uint8_t *data, size_t size) {
    cmsHPROFILE profile;
    cmsUInt32Number version;

    // Check if the size is sufficient to create a profile
    if (size < sizeof(cmsHPROFILE)) {
        return 0;
    }

    // Create a profile from the input data
    profile = cmsOpenProfileFromMem(data, size);
    if (profile == NULL) {
        return 0;
    }

    // Call the function-under-test
    version = cmsGetEncodedICCversion(profile);

    // Close the profile
    cmsCloseProfile(profile);

    return 0;
}