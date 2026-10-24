#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>  // Include Little CMS library header

// Remove 'extern "C"' as it is not needed in C code
int LLVMFuzzerTestOneInput_217(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    cmsToneCurve *toneCurve = NULL;
    cmsUInt32Number tableEntries;

    // Check if size is sufficient to create a tone curve
    if (size < sizeof(cmsFloat32Number)) {
        return 0;
    }

    // Create a tone curve with arbitrary parameters
    cmsFloat32Number gamma = 2.2f;  // Example gamma value
    toneCurve = cmsBuildGamma(NULL, gamma);

    if (toneCurve == NULL) {
        return 0;
    }

    // Call the function-under-test
    tableEntries = cmsGetToneCurveEstimatedTableEntries(toneCurve);

    // Clean up
    cmsFreeToneCurve(toneCurve);

    return 0;
}