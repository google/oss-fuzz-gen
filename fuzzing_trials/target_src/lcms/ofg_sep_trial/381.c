#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_381(const uint8_t *data, size_t size) {
    // Call the function-under-test
    const cmsCIExyY *result = cmsD50_xyY();

    // Use the result in some way to ensure it is not optimized away
    if (result != NULL) {
        volatile double x = result->x;
        volatile double y = result->y;
        volatile double Y = result->Y;
    }

    return 0;
}