#include <stdint.h>
#include <stddef.h>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_81(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    tjhandle handle = tjInitDecompress();
    tjscalingfactor scalingFactor;

    // Ensure data size is sufficient for creating a scaling factor
    if (size < sizeof(int) * 2) {
        tjDestroy(handle);
        return 0;
    }

    // Initialize scaling factor with values from data
    scalingFactor.num = ((int*)data)[0];
    scalingFactor.denom = ((int*)data)[1];

    // Ensure denominator is not zero to avoid division by zero
    if (scalingFactor.denom == 0) {
        scalingFactor.denom = 1;
    }

    // Call the function-under-test
    int result = tj3SetScalingFactor(handle, scalingFactor);

    // Clean up
    tjDestroy(handle);

    return result;
}