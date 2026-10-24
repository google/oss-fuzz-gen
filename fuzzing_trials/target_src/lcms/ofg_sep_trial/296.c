#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_296(const uint8_t *data, size_t size) {
    cmsHPROFILE hProfile = NULL;
    cmsUInt32Number flags;

    // Check if the size is sufficient to create a profile from memory
    if (size > 0) {
        // Create a memory-based profile
        hProfile = cmsOpenProfileFromMem(data, size);
    }

    // If the profile is successfully created, get the header flags
    if (hProfile != NULL) {
        flags = cmsGetHeaderFlags(hProfile);
        cmsCloseProfile(hProfile);
    }

    return 0;
}