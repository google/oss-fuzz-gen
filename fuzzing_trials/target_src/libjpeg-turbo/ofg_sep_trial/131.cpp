#include <stddef.h>
#include <stdint.h>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_131(const uint8_t *data, size_t size) {
    // Define and initialize the parameters for tj3JPEGBufSize function
    int width = 1;  // Minimum valid width
    int height = 1; // Minimum valid height
    int jpegSubsamp = TJSAMP_444; // Valid JPEG subsampling option

    // Call the function-under-test
    size_t bufferSize = tj3JPEGBufSize(width, height, jpegSubsamp);

    // Use the bufferSize in some way to avoid compiler optimizations removing the call
    volatile size_t result = bufferSize;
    (void)result;

    return 0;
}