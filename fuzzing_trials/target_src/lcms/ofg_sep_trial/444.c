#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

// Remove the extern "C" linkage specification for C++ and use a plain C function declaration
int LLVMFuzzerTestOneInput_444(const uint8_t *data, size_t size) {
    // Initialize a cmsContext
    cmsContext context = NULL;

    // Call the function-under-test
    cmsHPROFILE profile = cmsCreate_sRGBProfileTHR(context);

    // Check if the profile was created successfully
    if (profile != NULL) {
        // Do something with the profile if needed
        // ...

        // Release the profile
        cmsCloseProfile(profile);
    }

    return 0;
}