#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_312(const uint8_t *data, size_t size) {
    // Declare and initialize variables for the function parameters
    cmsContext context = cmsCreateContext(NULL, NULL);
    cmsUInt32Number nEntries = 256; // A typical number of entries for tone curves
    cmsUInt16Number *values;

    // Allocate memory for the values array
    values = (cmsUInt16Number *)malloc(nEntries * sizeof(cmsUInt16Number));
    if (values == NULL) {
        cmsDeleteContext(context);
        return 0;
    }

    // Initialize the values array using the input data
    for (cmsUInt32Number i = 0; i < nEntries; i++) {
        if (i < size / 2) {
            values[i] = (cmsUInt16Number)((data[2 * i] << 8) | data[2 * i + 1]);
        } else {
            values[i] = (cmsUInt16Number)(i * 257); // Default value if input data is insufficient
        }
    }

    // Call the function-under-test
    cmsToneCurve *toneCurve = cmsBuildTabulatedToneCurve16(context, nEntries, values);

    // Clean up
    if (toneCurve != NULL) {
        cmsFreeToneCurve(toneCurve);
    }
    free(values);
    cmsDeleteContext(context);

    return 0;
}