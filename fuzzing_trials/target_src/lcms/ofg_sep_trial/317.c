#include <stdint.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_317(const uint8_t *data, size_t size) {
    cmsHPROFILE profile;
    cmsUInt32Number intent;
    cmsBool lIsInput;

    // Ensure the size is sufficient to extract data
    if (size < sizeof(cmsUInt32Number) + sizeof(cmsBool)) {
        return 0;
    }

    // Create a dummy profile for testing
    profile = cmsCreate_sRGBProfile();
    if (profile == NULL) {
        return 0;
    }

    // Extract intent and lIsInput from data
    intent = *(cmsUInt32Number*)data;
    lIsInput = *(cmsBool*)(data + sizeof(cmsUInt32Number));

    // Call the function-under-test
    cmsUInt32Number result = cmsFormatterForPCSOfProfile(profile, intent, lIsInput);

    // Clean up
    cmsCloseProfile(profile);

    return 0;
}