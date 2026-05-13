#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_63(const uint8_t *data, size_t size) {
    // Ensure size is sufficient to extract an integer
    if (size < sizeof(cmsInt32Number)) {
        return 0;
    }

    // Create an array for the tone curve
    uint16_t table[256];
    for (int i = 0; i < 256; i++) {
        table[i] = i * 256; // Simple linear tone curve
    }

    // Initialize the cmsToneCurve structure with a valid table
    cmsToneCurve *toneCurve = cmsBuildTabulatedToneCurve16(NULL, 256, table);
    if (toneCurve == NULL) {
        return 0;
    }

    // Extract a cmsInt32Number from the data
    cmsInt32Number index = *(const cmsInt32Number *)data;

    // Call the function-under-test
    const cmsCurveSegment *segment = cmsGetToneCurveSegment(index, toneCurve);

    // Cleanup
    cmsFreeToneCurve(toneCurve);

    return 0;
}