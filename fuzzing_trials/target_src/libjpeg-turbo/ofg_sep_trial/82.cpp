#include <cstdint>
#include <cstdlib>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    // If the above path does not exist, try the other paths:
    // #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    // #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_82(const uint8_t *data, size_t size) {
    tjhandle handle = nullptr;
    tjscalingfactor scalingFactor;

    // Initialize the TurboJPEG decompressor
    handle = tjInitDecompress();
    if (!handle) {
        return 0; // Return if initialization fails
    }

    // Ensure size is sufficient for scaling factor initialization
    if (size < sizeof(tjscalingfactor)) {
        tjDestroy(handle);
        return 0;
    }

    // Extract scaling factor from input data
    scalingFactor.num = static_cast<int>(data[0] % 17 + 1); // Ensure num is between 1 and 17
    scalingFactor.denom = static_cast<int>(data[1] % 17 + 1); // Ensure denom is between 1 and 17

    // Call the function-under-test
    int result = tj3SetScalingFactor(handle, scalingFactor);

    // Clean up
    tjDestroy(handle);

    return 0;
}