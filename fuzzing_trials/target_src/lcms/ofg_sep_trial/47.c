#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_47(const uint8_t *data, size_t size) {
    // Call the function-under-test
    const cmsCIEXYZ *d50_xyz = cmsD50_XYZ();

    // Use the returned cmsCIEXYZ structure in some way to ensure it is accessed
    if (d50_xyz != NULL) {
        // Access the X, Y, and Z components
        volatile double x = d50_xyz->X;
        volatile double y = d50_xyz->Y;
        volatile double z = d50_xyz->Z;

        // Use the values to prevent compiler optimizations from removing the code
        (void)x;
        (void)y;
        (void)z;
    }

    return 0;
}