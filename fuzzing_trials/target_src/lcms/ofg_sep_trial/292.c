#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_292(const uint8_t *data, size_t size) {
    // Initialize the context
    cmsContext context = cmsCreateContext(NULL, NULL);

    // Check if the size is sufficient to create a profile
    if (size < sizeof(cmsHPROFILE)) {
        cmsDeleteContext(context);
        return 0;
    }

    // Create a profile from the input data
    cmsHPROFILE profile = cmsOpenProfileFromMem(data, size);

    // Clean up
    if (profile != NULL) {
        cmsCloseProfile(profile);
    }
    cmsDeleteContext(context);

    return 0;
}