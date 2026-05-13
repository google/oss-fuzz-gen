#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_329(const uint8_t *data, size_t size) {
    // Define and initialize variables for the function parameters
    cmsContext context = NULL; // Assuming default context
    cmsInt32Number type = 1; // Example type, can be varied
    cmsFloat64Number params[10]; // Example parameter array

    // Ensure the size is enough to fill the params array
    if (size < sizeof(params)) {
        return 0;
    }

    // Fill the params array with data from the input
    for (size_t i = 0; i < sizeof(params) / sizeof(params[0]); i++) {
        params[i] = ((cmsFloat64Number)data[i]) / 255.0; // Normalize data to [0, 1]
    }

    // Call the function-under-test
    cmsToneCurve *curve = cmsBuildParametricToneCurve(context, type, params);

    // Clean up if the curve was successfully created
    if (curve != NULL) {
        cmsFreeToneCurve(curve);
    }

    return 0;
}