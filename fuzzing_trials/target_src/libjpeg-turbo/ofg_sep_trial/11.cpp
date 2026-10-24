extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

#include <cstdint>
#include <cstdlib>
#include <iostream>

// Define the fuzzer test function
extern "C" int LLVMFuzzerTestOneInput_11(const uint8_t *data, size_t size) {
    // Initialize TurboJPEG compressor
    tjhandle compressor = tjInitCompress();
    if (!compressor) {
        std::cerr << "Failed to initialize TurboJPEG compressor" << std::endl;
        return 0;
    }

    // Define image parameters
    int width = 256;  // Example width
    int height = 256; // Example height
    int pixelFormat = TJPF_RGB; // Pixel format
    int jpegSubsamp = TJSAMP_444; // Subsampling option
    int jpegQual = 75; // JPEG quality

    // Allocate memory for the compressed image
    unsigned char *jpegBuf = nullptr;
    unsigned long jpegSize = 0;

    // Ensure the input data is large enough to simulate an image
    if (size < width * height * tjPixelSize[pixelFormat]) {
        tjDestroy(compressor);
        return 0;
    }

    // Call the function-under-test
    int result = tjCompress2(
        compressor,               // TurboJPEG handle
        data,                     // Source image buffer
        width,                    // Width of the source image
        0,                        // Pitch (0 for default)
        height,                   // Height of the source image
        pixelFormat,              // Pixel format of the source image
        &jpegBuf,                 // Destination buffer (compressed image)
        &jpegSize,                // Size of the compressed image
        jpegSubsamp,              // Subsampling option
        jpegQual,                 // JPEG quality
        TJFLAG_FASTDCT            // Flags
    );

    // Free the compressed image buffer
    if (jpegBuf) {
        tjFree(jpegBuf);
    }

    // Destroy the TurboJPEG compressor
    tjDestroy(compressor);

    return 0;
}