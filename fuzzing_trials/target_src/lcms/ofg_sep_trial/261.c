#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_261(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    cmsColorSpaceSignature colorSpaceSignature;
    cmsToneCurve *toneCurves[3]; // Assuming 3 channels for simplicity

    // Ensure the size is sufficient to read necessary data
    if (size < sizeof(cmsColorSpaceSignature) + 3 * sizeof(cmsUInt32Number)) {
        return 0;
    }

    // Initialize colorSpaceSignature
    colorSpaceSignature = *(cmsColorSpaceSignature *)data;
    data += sizeof(cmsColorSpaceSignature);
    size -= sizeof(cmsColorSpaceSignature);

    // Initialize toneCurves with non-NULL values
    for (int i = 0; i < 3; ++i) {
        cmsUInt32Number curveValue = *(cmsUInt32Number *)data;
        data += sizeof(cmsUInt32Number);
        size -= sizeof(cmsUInt32Number);

        // Create a tone curve from the curve value
        toneCurves[i] = cmsBuildGamma(NULL, curveValue / (double)UINT32_MAX);
    }

    // Call the function-under-test
    cmsHPROFILE profile = cmsCreateLinearizationDeviceLink(colorSpaceSignature, toneCurves);

    // Clean up
    if (profile != NULL) {
        cmsCloseProfile(profile);
    }
    
    for (int i = 0; i < 3; ++i) {
        if (toneCurves[i] != NULL) {
            cmsFreeToneCurve(toneCurves[i]);
        }
    }

    return 0;
}