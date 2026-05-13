#include <cstdint>
#include <cstdlib>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_3(const uint8_t *data, size_t size) {
    // Initialize a TurboJPEG handle
    tjhandle handle = tjInitDecompress();
    if (handle == nullptr) {
        return 0; // If initialization fails, exit early
    }

    // Ensure that the data and size are valid for further processing
    if (data != nullptr && size > 0) {
        // You can add more code here to utilize the data and size
        // For example, decompress the image data
        int width, height, jpegSubsamp, jpegColorspace;
        if (tjDecompressHeader3(handle, data, size, &width, &height, &jpegSubsamp, &jpegColorspace) == 0) {
            // If header decompression is successful, proceed with further operations
            // For example, allocate buffer and decompress the image
            unsigned char* buffer = (unsigned char*)malloc(width * height * tjPixelSize[TJPF_RGB]);
            if (buffer != nullptr) {
                tjDecompress2(handle, data, size, buffer, width, 0, height, TJPF_RGB, TJFLAG_FASTDCT);
                free(buffer);
            }
        }
    }

    // Clean up the TurboJPEG handle
    tjDestroy(handle);

    return 0;
}