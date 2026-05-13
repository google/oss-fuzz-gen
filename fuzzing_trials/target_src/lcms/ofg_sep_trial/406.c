#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_406(const uint8_t *data, size_t size) {
    if (size < sizeof(cmsCIEXYZ) * 4) {
        return 0; // Not enough data to fill all parameters
    }

    cmsCIEXYZ *Result = (cmsCIEXYZ *)malloc(sizeof(cmsCIEXYZ));
    const cmsCIEXYZ *SourceWhitePoint = (const cmsCIEXYZ *)(data);
    const cmsCIEXYZ *DestWhitePoint = (const cmsCIEXYZ *)(data + sizeof(cmsCIEXYZ));
    const cmsCIEXYZ *PCS = (const cmsCIEXYZ *)(data + 2 * sizeof(cmsCIEXYZ));

    // Ensure Result is not NULL
    if (Result == NULL) {
        return 0;
    }

    // Call the function-under-test
    cmsBool success = cmsAdaptToIlluminant(Result, SourceWhitePoint, DestWhitePoint, PCS);

    // Clean up
    free(Result);

    return 0;
}