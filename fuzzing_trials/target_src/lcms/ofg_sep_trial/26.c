#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_26(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    cmsContext context = cmsCreateContext(NULL, NULL);
    cmsUInt32Number nEntries = 10; // Arbitrary non-zero number of entries
    cmsFloat32Number floatArray[10]; // Array to hold float values

    // Ensure the size is sufficient to fill the floatArray
    if (size < sizeof(floatArray)) {
        cmsDeleteContext(context);
        return 0;
    }

    // Fill the floatArray with data from the input
    for (size_t i = 0; i < nEntries; i++) {
        floatArray[i] = ((cmsFloat32Number *)data)[i];
    }

    // Call the function-under-test
    cmsToneCurve *toneCurve = cmsBuildTabulatedToneCurveFloat(context, nEntries, floatArray);

    // Clean up
    if (toneCurve != NULL) {
        cmsFreeToneCurve(toneCurve);
    }
    cmsDeleteContext(context);

    return 0;
}