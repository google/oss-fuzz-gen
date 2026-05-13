#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h> // Include the Little CMS library header for cmsXYZ2xyY function

int LLVMFuzzerTestOneInput_20(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for the cmsCIEXYZ structure
    if (size < sizeof(cmsCIEXYZ)) {
        return 0;
    }

    // Create and initialize the cmsCIEXYZ structure from the input data
    cmsCIEXYZ xyz;
    xyz.X = ((double*)data)[0];
    xyz.Y = ((double*)data)[1];
    xyz.Z = ((double*)data)[2];

    // Create the cmsCIExyY structure to store the result
    cmsCIExyY xyY;

    // Call the function-under-test
    cmsXYZ2xyY(&xyY, &xyz);

    return 0;
}