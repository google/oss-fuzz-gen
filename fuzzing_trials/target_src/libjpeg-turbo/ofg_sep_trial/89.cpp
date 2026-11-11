#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstdio> // Include for FILE type

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
    #include "/src/libjpeg-turbo.main/src/jpeglib.h" // Include the correct header for J16SAMPLE
}

extern "C" int LLVMFuzzerTestOneInput_89(const uint8_t *data, size_t size) {
    // Initialize the TurboJPEG compressor
    tjhandle handle = tj3Init(TJINIT_COMPRESS);
    if (!handle) {
        return 0;
    }

    // Define the width, height, and pixel format for the image
    int width = 256;  // Example width
    int height = 256; // Example height
    int pitch = width * sizeof(uint16_t); // Assuming 16-bit samples, use uint16_t
    int pixelFormat = TJPF_RGBX; // Example pixel format

    // Allocate memory for the destination buffer
    unsigned char *jpegBuf = nullptr;
    size_t jpegSize = 0;

    // Ensure the input data is not null and size is sufficient
    if (data == nullptr || size < width * height * sizeof(uint16_t)) {
        tj3Destroy(handle);
        return 0;
    }

    // Cast the input data to uint16_t
    const uint16_t *srcBuf = reinterpret_cast<const uint16_t *>(data);

    // Call the function-under-test
    int result = tj3Compress16(handle, srcBuf, width, pitch, height, pixelFormat, &jpegBuf, &jpegSize);

    // Free the JPEG buffer if it was allocated
    if (jpegBuf) {
        tj3Free(jpegBuf);
    }

    // Destroy the TurboJPEG compressor handle
    tj3Destroy(handle);

    return 0;
}