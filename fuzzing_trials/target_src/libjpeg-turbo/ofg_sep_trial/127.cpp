#include <cstddef>
#include <cstdint>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_127(const uint8_t *data, size_t size) {
    // Initialize variables for width, height, subsamp, and align
    int width = 1;
    int height = 1;
    int subsamp = TJSAMP_444;  // Use a valid subsampling option
    int align = 1;

    // Ensure the size of data is sufficient to extract integers
    if (size >= 16) {
        // Extract integers from the input data
        width = static_cast<int>(data[0]) + 1;  // Avoid zero width
        height = static_cast<int>(data[4]) + 1; // Avoid zero height
        subsamp = static_cast<int>(data[8]) % 5; // Valid subsampling range
        align = static_cast<int>(data[12]) + 1;  // Avoid zero alignment
    }

    // Call the function-under-test
    unsigned long bufferSize = tjBufSizeYUV2(width, height, subsamp, align);

    // Return 0 to indicate successful execution
    return 0;
}