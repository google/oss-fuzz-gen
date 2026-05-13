#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_350(const uint8_t *data, size_t size) {
    // Define viewing conditions for initialization
    cmsViewingConditions viewingConditions = {
        .whitePoint = { 95.047, 100.0, 108.883 }, // D65 standard illuminant
        .Yb = 20.0,
        .La = 318.31,
        .surround = 1.0,
        .D_value = 0.0
    };

    // Initialize a cmsHANDLE
    cmsHANDLE handle = cmsCIECAM02Init(NULL, &viewingConditions);
    
    // Check if the handle is successfully created
    if (handle == NULL) {
        return 0;
    }

    // Utilize the input data if size is sufficient
    if (size >= sizeof(cmsCIEXYZ)) {
        cmsCIEXYZ *xyz = (cmsCIEXYZ *)data;
        cmsJCh jch;

        // Call the function-under-test with the input data
        cmsCIECAM02Forward(handle, xyz, &jch);
    }

    // Clean up
    cmsCIECAM02Done(handle);

    return 0;
}