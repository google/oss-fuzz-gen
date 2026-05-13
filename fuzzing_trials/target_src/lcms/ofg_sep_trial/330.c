#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_330(const uint8_t *data, size_t size) {
    if (size < sizeof(cmsFloat64Number)) {
        return 0;
    }

    // Initialize the cmsContext
    cmsContext context = cmsCreateContext(NULL, NULL);

    // Initialize cmsInt32Number
    cmsInt32Number type = 1; // Using a simple type for demonstration

    // Initialize cmsFloat64Number array
    cmsFloat64Number parameters[10];
    for (size_t i = 0; i < 10; i++) {
        parameters[i] = ((cmsFloat64Number)data[i % size]) / 255.0;
    }

    // Call the function-under-test
    cmsToneCurve *toneCurve = cmsBuildParametricToneCurve(context, type, parameters);

    // Clean up
    if (toneCurve != NULL) {
        cmsFreeToneCurve(toneCurve);
    }

    cmsDeleteContext(context);

    return 0;
}