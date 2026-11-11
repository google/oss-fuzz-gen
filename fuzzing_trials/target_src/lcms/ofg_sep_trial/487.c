#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_487(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient for a cmsFloat64Number
    if (size < sizeof(cmsFloat64Number)) {
        return 0;
    }

    // Initialize the parameters for cmsWhitePointFromTemp
    cmsCIExyY whitePoint;
    cmsFloat64Number temp;

    // Copy bytes from data to temp, ensuring proper casting
    temp = *(cmsFloat64Number*)data;

    // Call the function-under-test
    cmsBool result = cmsWhitePointFromTemp(&whitePoint, temp);

    // Use the result to prevent compiler optimizations (optional)
    if (result) {
        // Do something with whitePoint if needed
    }

    return 0;
}