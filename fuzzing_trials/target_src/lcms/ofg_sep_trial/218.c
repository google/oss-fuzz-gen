#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <lcms2.h>  // Include the Little CMS library header

int LLVMFuzzerTestOneInput_218(const uint8_t *data, size_t size) {
    if (size < sizeof(cmsFloat32Number)) {
        return 0;  // Not enough data to create a tone curve
    }

    // Create a tone curve using the provided data
    cmsToneCurve *toneCurve = cmsBuildTabulatedToneCurveFloat(NULL, size / sizeof(cmsFloat32Number), (cmsFloat32Number *)data);
    
    if (toneCurve == NULL) {
        return 0;  // Failed to create a tone curve
    }

    // Call the function-under-test
    cmsUInt32Number entries = cmsGetToneCurveEstimatedTableEntries(toneCurve);

    // Clean up
    cmsFreeToneCurve(toneCurve);

    return 0;
}