#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_282(const uint8_t *data, size_t size) {
    // Create a memory-based profile from the input data
    cmsHPROFILE hProfile = cmsOpenProfileFromMem((void*)data, (cmsUInt32Number)size);

    // Check if the profile was created successfully
    if (hProfile != NULL) {
        // Call the function-under-test
        cmsInt32Number tagCount = cmsGetTagCount(hProfile);

        // Close the profile to free resources
        cmsCloseProfile(hProfile);
    }

    return 0;
}