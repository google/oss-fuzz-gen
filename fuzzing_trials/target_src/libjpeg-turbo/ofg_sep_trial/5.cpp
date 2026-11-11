#include <cstdint>
#include <cstdlib>

extern "C" {
    // Include the correct path for the TurboJPEG header
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"

    // Include the function-under-test from the TurboJPEG library
    size_t tj3YUVBufSize(int width, int height, int subsamp, int align);
}

extern "C" int LLVMFuzzerTestOneInput_5(const uint8_t *data, size_t size) {
    // Declare and initialize the parameters for tj3YUVBufSize
    int width = 1;  // Minimum valid width
    int height = 1; // Minimum valid height
    int subsamp = TJSAMP_444; // A valid subsampling option
    int align = 1;  // Minimum valid alignment

    // Call the function-under-test with the initialized parameters
    size_t bufSize = tj3YUVBufSize(width, height, subsamp, align);

    // Use the buffer size to prevent compiler optimizations
    // This line is just to ensure the function call is not optimized away
    volatile size_t result = bufSize;

    return 0;
}