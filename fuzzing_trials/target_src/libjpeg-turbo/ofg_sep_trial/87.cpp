#include <cstdint>
#include <cstdlib>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_87(const uint8_t *data, size_t size) {
    // Initialize variables for the function call
    tjhandle handle = tjInitDecompress();
    if (handle == nullptr) {
        return 0; // Exit if the handle initialization fails
    }

    unsigned char* jpegBuf = const_cast<unsigned char*>(data);
    unsigned long jpegSize = static_cast<unsigned long>(size);

    // Allocate memory for the YUV buffer
    // Assuming a maximum size for YUV buffer, this should be adjusted according to specific needs
    int width = 640; // Example width
    int height = 480; // Example height
    int yuvSize = tjBufSizeYUV2(width, 4, height, TJSAMP_420);
    unsigned char* yuvBuf = (unsigned char*)malloc(yuvSize);

    // Call the function-under-test
    if (yuvBuf != nullptr) {
        tjDecompressToYUV(handle, jpegBuf, jpegSize, yuvBuf, 4); // 4 is the pitch (width step)
        free(yuvBuf);
    }

    // Clean up
    tjDestroy(handle);

    return 0;
}