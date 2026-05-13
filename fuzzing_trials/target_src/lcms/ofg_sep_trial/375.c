#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_375(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    cmsCIEXYZ XYZ;
    cmsCIExyY xyY;

    // Ensure that the size is sufficient to extract values for xyY
    if (size < sizeof(cmsCIExyY)) {
        return 0;
    }

    // Initialize xyY values from the input data
    xyY.x = (double)data[0] / 255.0;
    xyY.y = (double)data[1] / 255.0;
    xyY.Y = (double)data[2] / 255.0;

    // Call the function-under-test
    cmsxyY2XYZ(&XYZ, &xyY);

    return 0;
}