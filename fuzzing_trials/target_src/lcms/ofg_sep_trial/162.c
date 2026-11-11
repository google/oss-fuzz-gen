#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_162(const uint8_t *data, size_t size) {
    // Declare and initialize the parameters for the function-under-test
    cmsHPROFILE hProfile = NULL;
    cmsTagSignature tagSignature = (cmsTagSignature)0;

    // Ensure that the data size is sufficient to extract values for the parameters
    if (size >= sizeof(cmsTagSignature)) {
        // Use the data to initialize the tagSignature
        tagSignature = *(const cmsTagSignature*)data;

        // Open a profile to ensure hProfile is not NULL
        hProfile = cmsOpenProfileFromMem(data, size);
        if (hProfile != NULL) {
            // Call the function-under-test
            cmsTagSignature result = cmsTagLinkedTo(hProfile, tagSignature);

            // Close the profile after use
            cmsCloseProfile(hProfile);
        }
    }

    return 0;
}