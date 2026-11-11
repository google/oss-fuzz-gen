#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_94(const uint8_t *data, size_t size) {
    cmsHPROFILE hProfile = NULL;

    // Check if the input size is sufficient to create a profile
    if (size < sizeof(cmsHPROFILE)) {
        return 0;
    }

    // Create a profile using the input data
    hProfile = cmsOpenProfileFromMem(data, size);
    
    if (hProfile != NULL) {
        // Call the function-under-test
        cmsFloat64Number version = cmsGetProfileVersion(hProfile);

        // Close the profile after use
        cmsCloseProfile(hProfile);
    }

    return 0;
}