#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_180(const uint8_t *data, size_t size) {
    cmsHPROFILE profile = NULL;
    cmsFloat64Number result;

    // Check if the input size is sufficient to create a profile
    if (size < sizeof(cmsHPROFILE)) {
        return 0;
    }

    // Create a profile from the input data
    profile = cmsOpenProfileFromMem(data, size);
    if (profile == NULL) {
        return 0;
    }

    // Call the function under test
    result = cmsDetectTAC(profile);

    // Clean up
    cmsCloseProfile(profile);

    return 0;
}