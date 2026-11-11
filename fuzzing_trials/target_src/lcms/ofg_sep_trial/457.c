#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_457(const uint8_t *data, size_t size) {
    cmsToneCurve *toneCurve;
    cmsUInt32Number nEntries = 256; // A typical number of entries for a tone curve
    cmsFloat32Number values[256];

    // Initialize values for the tone curve
    for (cmsUInt32Number i = 0; i < nEntries; i++) {
        values[i] = (cmsFloat32Number)i / (cmsFloat32Number)(nEntries - 1);
    }

    // Create a tone curve using the values
    toneCurve = cmsBuildTabulatedToneCurveFloat(NULL, nEntries, values);

    if (toneCurve != NULL) {
        // Call the function-under-test
        cmsFreeToneCurve(toneCurve);
    }

    return 0;
}