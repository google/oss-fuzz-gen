#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_459(const uint8_t *data, size_t size) {
    // Initialize the CMS context
    cmsContext context = cmsCreateContext(NULL, NULL);

    // Check if the input data is sufficient to perform operations
    if (size < sizeof(cmsCIEXYZ)) {
        cmsDeleteContext(context);
        return 0;
    }

    // Use the input data to create a cmsCIEXYZ structure
    cmsCIEXYZ* xyz = (cmsCIEXYZ*)data;

    // Call the function-under-test
    cmsHPROFILE profile = cmsCreateXYZProfileTHR(context);

    // Clean up
    if (profile != NULL) {
        cmsCloseProfile(profile);
    }
    cmsDeleteContext(context);

    return 0;
}