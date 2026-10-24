#include <cstdint>
#include <cstdlib>
#include <cstdio>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_142(const uint8_t *data, size_t size) {
    // Define and initialize the parameters for tjBufSize
    int width = 1;  // Minimum width
    int height = 1; // Minimum height
    int jpegSubsamp = TJSAMP_444; // Use a valid subsampling option

    // Call the function-under-test
    unsigned long bufferSize = tjBufSize(width, height, jpegSubsamp);

    // Print the buffer size for debugging purposes
    printf("Buffer size: %lu\n", bufferSize);

    return 0;
}