#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_70(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    cmsUInt32Number nPoints = 256; // Example value, can vary
    cmsToneCurve *inputToneCurve = NULL;
    cmsToneCurve *reversedToneCurve = NULL;

    // Create a tone curve using the input data
    if (size >= sizeof(cmsUInt16Number) * nPoints) {
        inputToneCurve = cmsBuildTabulatedToneCurve16(NULL, nPoints, (cmsUInt16Number*)data);
    } else {
        // If not enough data, create a default tone curve
        cmsUInt16Number defaultValues[256];
        for (cmsUInt32Number i = 0; i < 256; i++) {
            defaultValues[i] = (cmsUInt16Number)i;
        }
        inputToneCurve = cmsBuildTabulatedToneCurve16(NULL, nPoints, defaultValues);
    }

    // Ensure inputToneCurve is not NULL
    if (inputToneCurve != NULL) {
        // Call the function-under-test
        reversedToneCurve = cmsReverseToneCurveEx(nPoints, inputToneCurve);

        // Clean up
        cmsFreeToneCurve(inputToneCurve);
        if (reversedToneCurve != NULL) {
            cmsFreeToneCurve(reversedToneCurve);
        }
    }

    return 0;
}