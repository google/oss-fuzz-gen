#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_210(const uint8_t *data, size_t size) {
    // Initialize the CMS context
    cmsContext context = cmsCreateContext(NULL, NULL);

    // Check if data is not NULL and size is sufficient for the function under test
    if (data != NULL && size > 0) {
        // Call the function-under-test
        cmsHPROFILE profile = cmsCreate_OkLabProfile(context);

        // Clean up: close the profile and delete the context
        if (profile != NULL) {
            cmsCloseProfile(profile);
        }
    }

    cmsDeleteContext(context);

    return 0;
}