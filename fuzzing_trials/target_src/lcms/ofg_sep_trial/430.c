#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_430(const uint8_t *data, size_t size) {
    cmsHPROFILE hProfile = NULL;

    // Ensure the data is not NULL and has a reasonable size
    if (data == NULL || size == 0) {
        return 0;
    }

    // Create a memory-based profile using the input data
    hProfile = cmsOpenProfileFromMem(data, size);
    if (hProfile == NULL) {
        return 0;
    }

    // Call the function-under-test
    cmsColorSpaceSignature colorSpace = cmsGetColorSpace(hProfile);

    // Clean up
    cmsCloseProfile(hProfile);

    return 0;
}