#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_25(const uint8_t *data, size_t size) {
    // Initialize variables for the function-under-test
    cmsContext context = cmsCreateContext(NULL, NULL);
    cmsUInt32Number nEntries = 256; // A reasonable default number of entries
    cmsFloat32Number *table = (cmsFloat32Number *)malloc(nEntries * sizeof(cmsFloat32Number));

    // Ensure table is not NULL
    if (table == NULL) {
        cmsDeleteContext(context);
        return 0;
    }

    // Fill the table with some values derived from the input data
    for (cmsUInt32Number i = 0; i < nEntries; i++) {
        table[i] = (i < size) ? (cmsFloat32Number)data[i] / 255.0f : 0.0f;
    }

    // Call the function-under-test
    cmsToneCurve *toneCurve = cmsBuildTabulatedToneCurveFloat(context, nEntries, table);

    // Clean up
    if (toneCurve != NULL) {
        cmsFreeToneCurve(toneCurve);
    }
    free(table);
    cmsDeleteContext(context);

    return 0;
}

#ifdef __cplusplus
}
#endif