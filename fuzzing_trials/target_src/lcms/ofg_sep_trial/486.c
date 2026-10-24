#include <stdint.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_486(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient for extracting a cmsFloat64Number
    if (size < sizeof(cmsFloat64Number)) {
        return 0;
    }

    // Extract a cmsFloat64Number from the input data
    cmsFloat64Number temperature;
    memcpy(&temperature, data, sizeof(cmsFloat64Number));

    // Initialize a cmsCIExyY structure
    cmsCIExyY whitePoint;

    // Call the function-under-test
    cmsBool result = cmsWhitePointFromTemp(&whitePoint, temperature);

    // Use the result to prevent compiler optimizations (optional)
    if (result) {
        // Do something with whitePoint if needed
    }

    return 0;
}