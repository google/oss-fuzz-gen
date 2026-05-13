#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_376(const uint8_t *data, size_t size) {
    // Declare and initialize the cmsCIEXYZ and cmsCIExyY structures
    cmsCIEXYZ xyz;
    cmsCIExyY xyY;

    // Ensure the input data is large enough to populate the structures
    if (size < sizeof(cmsCIExyY)) {
        return 0;
    }

    // Populate the cmsCIExyY structure with data from the input
    xyY.x = ((double)data[0] / 255.0);
    xyY.y = ((double)data[1] / 255.0);
    xyY.Y = ((double)data[2] / 255.0);

    // Call the function-under-test
    cmsxyY2XYZ(&xyz, &xyY);

    return 0;
}