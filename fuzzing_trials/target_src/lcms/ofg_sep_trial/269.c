#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_269(const uint8_t *data, size_t size) {
    // Initialize cmsContext
    cmsContext context = cmsCreateContext(NULL, NULL);
    if (context == NULL) {
        return 0;
    }

    // Initialize cmsViewingConditions
    cmsViewingConditions viewingConditions;
    cmsCIEXYZ whitePoint = {0.95047, 1.00000, 1.08883}; // D65 standard illuminant
    cmsFloat64Number Yb = 20.0; // Luminance of background
    cmsFloat64Number La = 318.31; // Adapting field luminance
    cmsFloat64Number surround = 2.0; // Surround condition

    viewingConditions.whitePoint = whitePoint;
    viewingConditions.Yb = Yb;
    viewingConditions.La = La;
    viewingConditions.surround = surround;
    viewingConditions.D_value = 1.0; // Degree of adaptation

    // Call the function-under-test
    cmsHANDLE handle = cmsCIECAM02Init(context, &viewingConditions);

    // Clean up
    if (handle != NULL) {
        cmsCIECAM02Done(handle);
    }
    cmsDeleteContext(context);

    return 0;
}