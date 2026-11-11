#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_128(const uint8_t *data, size_t size) {
    cmsHPROFILE hProfile;
    cmsProfileClassSignature deviceClass;

    // Check if the size is sufficient to create a profile
    if (size < sizeof(cmsHPROFILE)) {
        return 0;
    }

    // Create a memory-based profile using the input data
    hProfile = cmsOpenProfileFromMem(data, size);
    if (hProfile == NULL) {
        return 0;
    }

    // Call the function under test
    deviceClass = cmsGetDeviceClass(hProfile);

    // Close the profile
    cmsCloseProfile(hProfile);

    return 0;
}