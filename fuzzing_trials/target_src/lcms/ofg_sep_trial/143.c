#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_143(const uint8_t *data, size_t size) {
    // Call the function-under-test with input data
    cmsHPROFILE profile = cmsOpenProfileFromMem(data, size);

    // Check if the profile is successfully created
    if (profile != NULL) {
        // Do something with the profile if needed, for now, we just close it
        cmsCloseProfile(profile);
    }

    return 0;
}