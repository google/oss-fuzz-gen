#include <stdint.h>
#include <stddef.h>
#include <string.h> // Include string.h for memcpy
#include <lcms2.h>

int LLVMFuzzerTestOneInput_480(const uint8_t *data, size_t size) {
    if (size < sizeof(cmsCIExyY)) {
        return 0; // Not enough data to fill cmsCIExyY structure
    }

    cmsCIExyY whitePoint;
    cmsFloat64Number temperature;

    // Copy data into the cmsCIExyY structure
    memcpy(&whitePoint, data, sizeof(cmsCIExyY));

    // Call the function-under-test
    cmsBool result = cmsTempFromWhitePoint(&temperature, &whitePoint);

    // Use the result to avoid any compiler optimizations that might skip the call
    if (result) {
        // Do something with temperature if needed, for now, just a no-op
        (void)temperature;
    }

    return 0;
}