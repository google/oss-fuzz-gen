#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_389(const uint8_t *data, size_t size) {
    // Ensure the size is non-zero to avoid passing NULL to the function
    if (size == 0) {
        return 0;
    }

    // Call the function-under-test
    cmsHPROFILE profile = cmsOpenProfileFromMem((const void *)data, (cmsUInt32Number)size);

    // If a valid profile is returned, close it to avoid memory leaks
    if (profile != NULL) {
        cmsCloseProfile(profile);
    }

    return 0;
}