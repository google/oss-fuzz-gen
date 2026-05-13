#include <cstdint>
#include <cstdlib>
#include <cstdio>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_153(const uint8_t *data, size_t size) {
    // Declare and initialize the variables for the function parameters
    int width = 1;  // Initialize to a non-zero value
    int height = 1; // Initialize to a non-zero value
    int subsamp = TJSAMP_444; // Use a valid subsampling value

    // Call the function-under-test
    unsigned long bufferSize = TJBUFSIZEYUV(width, height, subsamp);

    // Print the result for debugging purposes
    printf("Buffer Size: %lu\n", bufferSize);

    return 0;
}