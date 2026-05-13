#include <cstdint>
#include <cstdlib>
#include <cstdio>

// Include the necessary header for the function-under-test
extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

// Define the fuzzing function
extern "C" int LLVMFuzzerTestOneInput_154(const uint8_t *data, size_t size) {
    // Declare and initialize the parameters for the function-under-test
    int width = 1;  // Minimum valid value
    int height = 1; // Minimum valid value
    int subsamp = TJSAMP_444; // A valid subsampling option

    // Call the function-under-test
    unsigned long bufferSize = TJBUFSIZEYUV(width, height, subsamp);

    // Print the result (for debugging purposes, can be removed in production)
    printf("Buffer Size: %lu\n", bufferSize);

    return 0;
}