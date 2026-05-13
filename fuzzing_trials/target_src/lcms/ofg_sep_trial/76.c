#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_76(const uint8_t *data, size_t size) {
    // Ensure there is enough data to proceed
    if (size < sizeof(cmsUInt16Number)) {
        return 0;
    }

    // Initialize a cmsToneCurve object
    cmsToneCurve* toneCurve = cmsBuildGamma(NULL, 2.2); // Using a gamma of 2.2 as an example

    // Read a cmsUInt16Number from the input data
    cmsUInt16Number inputNumber = *(const cmsUInt16Number*)data;

    // Call the function-under-test
    cmsUInt16Number result = cmsEvalToneCurve16(toneCurve, inputNumber);

    // Clean up
    cmsFreeToneCurve(toneCurve);

    return 0;
}