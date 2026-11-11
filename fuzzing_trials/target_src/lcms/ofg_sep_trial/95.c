#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_95(const uint8_t *data, size_t size) {
    // Initialize the LCMS context
    cmsContext context = cmsCreateContext(NULL, NULL);
    if (context == NULL) {
        return 0;
    }

    // Create a memory-based profile from the input data
    cmsHPROFILE hProfile = cmsOpenProfileFromMemTHR(context, data, size);
    if (hProfile == NULL) {
        cmsDeleteContext(context);
        return 0;
    }

    // Call the function-under-test
    cmsFloat64Number version = cmsGetProfileVersion(hProfile);

    // Clean up
    cmsCloseProfile(hProfile);
    cmsDeleteContext(context);

    return 0;
}