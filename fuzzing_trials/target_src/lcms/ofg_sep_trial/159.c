#include <stdint.h>
#include <stdbool.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_159(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient to extract necessary parameters
    if (size < sizeof(cmsUInt32Number) + sizeof(cmsBool)) {
        return 0;
    }

    // Initialize parameters for cmsFormatterForColorspaceOfProfile
    cmsHPROFILE hProfile = cmsOpenProfileFromMem(data, size);
    if (hProfile == NULL) {
        return 0;
    }
    
    cmsUInt32Number dwFlags = *(const cmsUInt32Number *)(data);
    cmsBool lIsInput = *(const cmsBool *)(data + sizeof(cmsUInt32Number));

    // Call the function-under-test
    cmsUInt32Number result = cmsFormatterForColorspaceOfProfile(hProfile, dwFlags, lIsInput);

    // Clean up
    cmsCloseProfile(hProfile);

    return 0;
}