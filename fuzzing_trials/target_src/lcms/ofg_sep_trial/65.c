#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_65(const uint8_t *data, size_t size) {
    // Ensure the data size is large enough to create a tone curve
    if (size < sizeof(uint16_t)) {
        return 0;
    }

    // Create a tone curve using the provided data
    cmsToneCurve *toneCurve = cmsBuildTabulatedToneCurve16(NULL, size / sizeof(uint16_t), (const uint16_t*)data);
    if (toneCurve == NULL) {
        return 0;
    }

    // Call the function-under-test
    cmsBool result = cmsIsToneCurveDescending(toneCurve);

    // Clean up
    cmsFreeToneCurve(toneCurve);

    return 0;
}