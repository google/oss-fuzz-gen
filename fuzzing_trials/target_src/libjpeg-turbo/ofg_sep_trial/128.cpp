#include <cstdint>
#include <cstdlib>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_128(const uint8_t *data, size_t size) {
    // Declare and initialize the parameters for tjBufSizeYUV2
    int width = 1;  // Minimum valid width
    int height = 1; // Minimum valid height
    int subsamp = TJSAMP_420; // Common subsampling option
    int align = 1; // Minimum valid alignment

    // Call the function-under-test
    unsigned long bufferSize = tjBufSizeYUV2(width, height, subsamp, align);

    // Use the result in some way to avoid compiler optimizations removing the call
    (void)bufferSize;

    return 0;
}