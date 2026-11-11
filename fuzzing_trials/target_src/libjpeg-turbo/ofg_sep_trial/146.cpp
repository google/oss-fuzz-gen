#include <cstdint>
#include <cstdlib>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_146(const uint8_t *data, size_t size) {
    // Declare and initialize variables for the tjPlaneSizeYUV function parameters
    int width = 1;  // Minimum width to avoid zero or negative values
    int height = 1; // Minimum height to avoid zero or negative values
    int subsamp = TJSAMP_420; // Using a valid subsampling option
    int align = 1; // Minimum alignment
    int componentID = 0; // Valid component ID

    // Call the function-under-test
    unsigned long planeSize = tjPlaneSizeYUV(componentID, width, height, subsamp, align);

    // Use the result to avoid compiler optimizations that remove the call
    (void)planeSize;

    return 0;
}