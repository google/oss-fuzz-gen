#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_429(const uint8_t *data, size_t size) {
    cmsHPROFILE hProfile = NULL;
    cmsColorSpaceSignature colorSpace;

    // Ensure the data is large enough to be a valid profile
    if (size < sizeof(cmsHPROFILE)) {
        return 0;
    }

    // Create a memory-based profile from the input data
    hProfile = cmsOpenProfileFromMem(data, size);
    if (hProfile == NULL) {
        return 0;
    }

    // Call the function-under-test
    colorSpace = cmsGetColorSpace(hProfile);

    // Close the profile after use
    cmsCloseProfile(hProfile);

    return 0;
}