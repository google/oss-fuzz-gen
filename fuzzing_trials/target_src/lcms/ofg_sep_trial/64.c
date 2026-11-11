#include <stdint.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_64(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient to extract necessary values
    if (size < sizeof(cmsInt32Number)) {
        return 0;
    }

    // Extract a cmsInt32Number from the data
    cmsInt32Number index = *((const cmsInt32Number *)data);

    // Create a dummy cmsToneCurve for testing
    cmsToneCurve *toneCurve = cmsBuildGamma(NULL, 2.2); // Example gamma value

    // Call the function-under-test
    const cmsCurveSegment *segment = cmsGetToneCurveSegment(index, toneCurve);

    // Clean up
    if (toneCurve != NULL) {
        cmsFreeToneCurve(toneCurve);
    }

    return 0;
}