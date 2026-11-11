#include <cstdint>
#include <cstdlib>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_145(const uint8_t *data, size_t size) {
    // Declare and initialize variables for the function parameters
    int width = 1;  // Minimum width
    int height = 1; // Minimum height
    int subsamp = TJSAMP_420; // Use a valid subsampling option
    int plane = 0; // Plane index, typically starting from 0
    int align = 1; // Minimum alignment

    // Call the function-under-test
    unsigned long result = tjPlaneSizeYUV(plane, width, align, height, subsamp);

    // Use the result in some way to avoid compiler optimizations removing the call
    volatile unsigned long use_result = result;
    (void)use_result;

    return 0;
}