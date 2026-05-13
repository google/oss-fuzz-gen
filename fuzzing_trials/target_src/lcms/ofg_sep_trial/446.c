#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_446(const uint8_t *data, size_t size) {
    cmsHPROFILE profile;

    // Check if the size is sufficient for creating a profile
    if (size < sizeof(cmsHPROFILE)) {
        return 0;
    }

    // Create a profile from memory using the input data
    profile = cmsOpenProfileFromMem(data, size);
    if (profile == NULL) {
        return 0;
    }

    // Call the function-under-test
    cmsBool result = cmsCloseProfile(profile);

    return 0;
}