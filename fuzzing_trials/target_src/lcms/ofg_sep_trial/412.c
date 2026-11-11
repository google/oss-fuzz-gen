#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

// The LLVMFuzzerTestOneInput function is the entry point for the fuzzer.
int LLVMFuzzerTestOneInput_412(const uint8_t *data, size_t size) {
    // Declare and initialize variables for the function parameters.
    cmsHPROFILE hProfile = NULL;
    cmsTagSignature tagSignature;

    // Ensure that size is sufficient to extract a cmsTagSignature.
    if (size < sizeof(cmsTagSignature)) {
        return 0;
    }

    // Initialize the tagSignature from the input data.
    tagSignature = *(cmsTagSignature *)data;

    // Create a dummy profile to ensure hProfile is not NULL.
    hProfile = cmsCreate_sRGBProfile();
    if (hProfile == NULL) {
        return 0;
    }

    // Call the function-under-test.
    cmsBool result = cmsIsTag(hProfile, tagSignature);

    // Clean up resources.
    cmsCloseProfile(hProfile);

    // Return 0 to indicate the fuzzer should continue.
    return 0;
}