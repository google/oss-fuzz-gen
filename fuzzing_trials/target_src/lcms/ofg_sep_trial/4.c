#include <stdint.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_4(const uint8_t *data, size_t size) {
    // Initialize variables
    cmsContext context = cmsCreateContext(NULL, NULL);
    cmsColorSpaceSignature colorSpace = cmsSigRgbData; // Example color space
    cmsToneCurve *toneCurves[3]; // Assuming RGB
    cmsHPROFILE profile = NULL;
    int i;

    // Create tone curves
    for (i = 0; i < 3; i++) {
        toneCurves[i] = cmsBuildGamma(context, 2.2); // Example gamma value
        if (toneCurves[i] == NULL) {
            goto cleanup;
        }
    }

    // Call the function-under-test
    profile = cmsCreateLinearizationDeviceLinkTHR(context, colorSpace, (const cmsToneCurve **)toneCurves);

    // Cleanup
    if (profile != NULL) {
        cmsCloseProfile(profile);
    }

cleanup:
    for (i = 0; i < 3; i++) {
        if (toneCurves[i] != NULL) {
            cmsFreeToneCurve(toneCurves[i]);
        }
    }
    cmsDeleteContext(context);

    return 0;
}