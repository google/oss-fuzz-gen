#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_351(const uint8_t *data, size_t size) {
    // Define viewing conditions
    cmsViewingConditions viewingConditions = {
        .whitePoint = {0.95047, 1.00000, 1.08883}, // D65 white point
        .Yb = 20.0, // Background luminance
        .La = 64.0, // Adapting field luminance
        .surround = 1.0, // Surround factor
        .D_value = 0.0 // Degree of adaptation
    };

    // Initialize a cmsHANDLE for testing
    cmsHANDLE handle = cmsCIECAM02Init(NULL, &viewingConditions);
    
    // Ensure the handle is not NULL
    if (handle != NULL) {
        // Call the function-under-test
        cmsCIECAM02Done(handle);
    }

    return 0;
}