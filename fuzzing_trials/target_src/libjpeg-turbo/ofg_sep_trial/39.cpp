#include <cstddef>
#include <cstdint>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"

    // Function signature from the task
    size_t tj3YUVPlaneSize(int, int, int, int, int);
}

extern "C" int LLVMFuzzerTestOneInput_39(const uint8_t *data, size_t size) {
    // Declare and initialize variables for the function parameters
    int width = 1;  // Minimum valid width
    int height = 1; // Minimum valid height
    int subsamp = TJSAMP_420; // Common subsampling option
    int align = 1; // Minimum alignment
    int plane = 0; // Plane index, assuming 0 is valid

    // Call the function-under-test with the initialized parameters
    size_t yuvPlaneSize = tj3YUVPlaneSize(width, height, subsamp, align, plane);

    // Use the result to avoid compiler optimizations that remove the call
    (void)yuvPlaneSize;

    return 0;
}