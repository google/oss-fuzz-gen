#include <stdint.h>
#include <stddef.h>
#include "lcms2.h" // Ensure that Little CMS library headers are included

// Remove 'extern "C"' since it is not needed in C code
int LLVMFuzzerTestOneInput_53(const uint8_t *data, size_t size) {
    // Declare and initialize the integer parameter for the function
    int colorSpaceType = 0;

    // Ensure the size is sufficient to read an integer
    if (size >= sizeof(int)) {
        // Copy the first bytes of data into colorSpaceType
        colorSpaceType = *(const int *)data;
    }

    // Call the function-under-test
    cmsColorSpaceSignature result = _cmsICCcolorSpace(colorSpaceType);

    // Use the result in some way to avoid compiler optimizations removing the call
    (void)result;

    return 0;
}