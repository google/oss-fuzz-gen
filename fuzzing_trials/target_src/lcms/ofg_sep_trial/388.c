#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_388(const uint8_t *data, size_t size) {
    // Ensure that the data size is non-zero to avoid passing NULL pointers
    if (size == 0) {
        return 0;
    }

    // Call the function-under-test with the provided data
    cmsHPROFILE profile = cmsOpenProfileFromMem((const void *)data, (cmsUInt32Number)size);

    // If the profile was successfully opened, close it
    if (profile != NULL) {
        cmsCloseProfile(profile);
    }

    return 0;
}