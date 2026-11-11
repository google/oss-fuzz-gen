#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_45(const uint8_t *data, size_t size) {
    cmsHPROFILE hProfile = NULL;
    cmsUInt32Number headerModel;

    // Ensure the data is not empty and can be used to create a profile
    if (size > 0) {
        // Create a memory-based profile using the input data
        hProfile = cmsOpenProfileFromMem(data, size);

        // Check if the profile was created successfully
        if (hProfile != NULL) {
            // Call the function-under-test
            headerModel = cmsGetHeaderModel(hProfile);

            // Close the profile to free resources
            cmsCloseProfile(hProfile);
        }
    }

    return 0;
}