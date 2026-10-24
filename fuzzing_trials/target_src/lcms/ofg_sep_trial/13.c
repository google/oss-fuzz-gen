#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_13(const uint8_t *data, size_t size) {
    cmsHPROFILE hProfile;
    cmsUInt32Number intent;
    cmsUInt32Number flags;
    cmsBool result;

    // Check if the data size is sufficient to extract necessary parameters
    if (size < sizeof(cmsUInt32Number) * 2) {
        return 0;
    }

    // Initialize the parameters
    hProfile = cmsOpenProfileFromMem(data, size);
    intent = *(const cmsUInt32Number *)(data);
    flags = *(const cmsUInt32Number *)(data + sizeof(cmsUInt32Number));

    // Ensure hProfile is valid
    if (hProfile != NULL) {
        // Call the function-under-test
        result = cmsIsIntentSupported(hProfile, intent, flags);

        // Close the profile after use
        cmsCloseProfile(hProfile);
    }

    return 0;
}