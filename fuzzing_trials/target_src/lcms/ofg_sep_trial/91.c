#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_91(const uint8_t *data, size_t size) {
    cmsHPROFILE hProfile;
    cmsContext context;

    // Ensure that the input size is sufficient for creating a profile
    if (size < sizeof(cmsHPROFILE)) {
        return 0;
    }

    // Create a profile from the input data
    hProfile = cmsOpenProfileFromMem(data, size);
    if (hProfile == NULL) {
        return 0;
    }

    // Call the function-under-test
    context = cmsGetProfileContextID(hProfile);

    // Close the profile
    cmsCloseProfile(hProfile);

    return 0;
}